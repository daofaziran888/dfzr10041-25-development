"""拾音工坊隔离解除管道：隔离行 → 来源核验 → 重新解析 → 解除批次 → 正式分类入库。

采集作业中格式可用但缺少来源归属凭据的日志行先进入隔离区，不允许直接进入
classify_events。解除流程：

1. 按来源核验原行：原日志位置（source_id + 文件位置）必须与隔离快照一致，
   位置没变但正文被替换（raw_checksum 变化）单独拒绝，不能复用另一份成功
   解析与归属凭据；
2. 重新解析：仍走来源格式校验 + parser_rule 正则，解析不过或凭据仍缺的行
   继续隔离；
3. 生成解除批次（解除单），状态按 待补证 → 核验 → 结清 流转；
4. 解除批次获准后才解除 quarantined 标记，交给 IngestPipeline.classify_events
   写库存；按原行核销（LINE）可逐条放行，按组结清（GROUP）必须整组都核清。

事件时间一律从原日志时间戳 + 已证实的来源时区还原，绝不用放行时的当前时间。
同一放行（含回执超时后的并发重试）只落库一次。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from typing import Any

from app.core.models import (
    EventRecord, LogEntry, LogSourceConfig, ParseResultStatus, ParseRule,
)
from app.core.pipeline import IngestPipeline, extract_event_time


class ReleaseMode(Enum):
    """解除单核销方式。"""
    LINE = "line"    # 按原行核销：核验通过的行当班即可放行
    GROUP = "group"  # 按组结清：整组归属都核清后才一起分类入库


class ReleaseOrderStatus(Enum):
    """解除单状态：待补证 → 核验 → 结清。"""
    PENDING_EVIDENCE = "待补证"
    VERIFYING = "核验"
    SETTLED = "结清"


class ItemVerdict(Enum):
    """解除单内行的核验结论。"""
    PENDING = "待核验"
    PASSED = "核验通过"
    EVIDENCE_MISSING = "凭据缺失"
    TAMPERED = "正文被替换"
    UNPARSEABLE = "无法解析"
    RELEASED = "已放行"


class QuarantineError(RuntimeError):
    """隔离解除流程的非法操作。"""


@dataclass
class SourceCredential:
    """来源归属凭据：证实某来源位置上的机器归属。"""
    credential_id: str
    source_id: str
    source_location: str
    host_identity: str
    issued_at: datetime = field(default_factory=datetime.now)
    valid: bool = True


@dataclass
class ReleaseItem:
    """解除批次内的一行：串联原日志、核验结论与实际使用的凭据。"""
    entry: LogEntry
    raw_checksum_snapshot: str
    verdict: ItemVerdict = ItemVerdict.PENDING
    evidence_id: str = ""
    reject_reason: str = ""
    released_at: datetime | None = None


@dataclass
class ReleaseOrder:
    """解除隔离批次（解除单）。"""
    order_id: str
    source_id: str
    mode: ReleaseMode
    items: list[ReleaseItem]
    status: ReleaseOrderStatus = ReleaseOrderStatus.PENDING_EVIDENCE
    created_at: datetime = field(default_factory=datetime.now)
    approved_at: datetime | None = None
    # 幂等放行记录：line_key → 已落库事件指纹
    released_keys: set[str] = field(default_factory=set)


@dataclass
class ReleaseReceipt:
    """放行回执——模拟入库成功但回执超时的场景也能安全重试。"""
    order_id: str
    released_line_keys: list[str]
    stored_event_count: int
    already_settled: bool


class QuarantineManager:
    """隔离区与解除批次的领域服务。"""

    def __init__(self, pipeline: IngestPipeline):
        self.pipeline = pipeline
        self._quarantine: dict[str, LogEntry] = {}
        self._credentials: dict[str, SourceCredential] = {}
        self._orders: dict[str, ReleaseOrder] = {}
        self._order_seq = 0
        self._handoff_evidence: list[dict[str, Any]] = []

    # ---------- 隔离 ----------

    def quarantine_entry(self, entry: LogEntry, source_location: str) -> LogEntry:
        """把一条因归属凭据缺失被隔离的日志收入隔离区。

        保留原日志位置与原行快照（raw_checksum），后续核验以此为准。
        """
        entry.quarantined = True
        entry.source_location = source_location
        entry.parse_status = ParseResultStatus.CREDENTIAL_MISSING
        self._quarantine[self._line_key(entry.source_id, source_location)] = entry
        return entry

    def get_quarantined(self, source_id: str | None = None) -> list[LogEntry]:
        return [
            entry for entry in self._quarantine.values()
            if source_id is None or entry.source_id == source_id
        ]

    # ---------- 归属凭据 ----------

    def register_credential(self, credential: SourceCredential) -> SourceCredential:
        """登记/补报一份来源归属凭据。"""
        self._credentials[credential.credential_id] = credential
        return credential

    def find_credential(self, source_id: str, source_location: str) -> SourceCredential | None:
        for credential in self._credentials.values():
            if (credential.source_id == source_id
                    and credential.source_location == source_location
                    and credential.valid):
                return credential
        return None

    def refresh_from_source(self, source_id: str, source_location: str,
                            current_line: str) -> LogEntry:
        """按来源位置重新拉取当前文件内容，刷新隔离行原行。

        隔离区记住的是来源位置；核验前若文件在同位置被重写，先刷新再核验，
        由来源格式校验与解析规则决定新内容能否解除。刷新会同步更新所有
        未结清解除单内该行的快照基线——这是经确认的重新拉取，区别于核验时
        才发现的正文偷换（后者按 TAMPERED 拒绝）。
        """
        key = self._line_key(source_id, source_location)
        entry = self._quarantine.get(key)
        if entry is None:
            raise QuarantineError(f"隔离行不存在：{key}")
        entry.raw_line = current_line
        for order in self._orders.values():
            if order.status == ReleaseOrderStatus.SETTLED:
                continue
            for item in order.items:
                if self._line_key(item.entry.source_id,
                                  item.entry.source_location) == key:
                    item.raw_checksum_snapshot = entry.raw_checksum()
        return entry

    # ---------- 解除批次（解除单） ----------

    def create_release_order(self, source_id: str, source_locations: list[str],
                             mode: ReleaseMode) -> ReleaseOrder:
        """针对同一来源的一批隔离行生成解除单，初始状态为待补证。"""
        items: list[ReleaseItem] = []
        for location in source_locations:
            key = self._line_key(source_id, location)
            entry = self._quarantine.get(key)
            if entry is None:
                raise QuarantineError(f"隔离行不存在：{key}")
            items.append(ReleaseItem(entry=entry, raw_checksum_snapshot=entry.raw_checksum()))
        self._order_seq += 1
        order = ReleaseOrder(
            order_id=f"RELS-{self._order_seq:06d}",
            source_id=source_id,
            mode=mode,
            items=items,
        )
        # 建单时若已有凭据可直接核验，否则停在待补证。
        if any(self.find_credential(source_id, item.entry.source_location) for item in items):
            order.status = ReleaseOrderStatus.VERIFYING
        self._orders[order.order_id] = order
        return order

    def submit_evidence(self, order_id: str, credential_id: str) -> ReleaseOrder:
        """值班员补报凭据：待补证 → 核验。凭据与解除单来源必须一致。"""
        order = self._require_order(order_id)
        if order.status == ReleaseOrderStatus.SETTLED:
            raise QuarantineError(f"解除单 {order_id} 已结清，不能再补证")
        credential = self._credentials.get(credential_id)
        if credential is None or not credential.valid:
            raise QuarantineError(f"凭据 {credential_id} 无效或不存在")
        if credential.source_id != order.source_id:
            raise QuarantineError("凭据来源与解除单来源不一致，不能跨来源复用归属凭据")
        order.status = ReleaseOrderStatus.VERIFYING
        return order

    def verify_order(self, order_id: str, source: LogSourceConfig,
                     rule: ParseRule) -> ReleaseOrder:
        """对解除单逐行做来源核验 + 重新解析。

        核验顺序与结论：
        1. 来源位置一致（取单即保证），但原行正文与隔离快照不一致 → 正文被替换，
           单独拒绝，不能复用另一份成功解析和归属凭据；
        2. 无有效归属凭据 → 凭据缺失，继续隔离；
        3. 来源格式校验或正则解析失败 → 无法解析，继续隔离；
        4. 全部通过 → 核验通过，并按来源时区还原事件时间。
        """
        order = self._require_order(order_id)
        if order.status != ReleaseOrderStatus.VERIFYING:
            raise QuarantineError("解除单须处于核验状态才能核验，请先补报凭据")
        for item in order.items:
            entry = item.entry
            # 已放行的行（按原行核销中先放行的 A）核验结论固化，不被后续
            # 补证轮次覆盖；其余行每轮都按最新凭据与原行快照重新核验。
            if item.verdict == ItemVerdict.RELEASED:
                continue
            if entry.raw_checksum() != item.raw_checksum_snapshot:
                item.verdict = ItemVerdict.TAMPERED
                item.reject_reason = "来源位置未变但日志正文已被替换"
                continue
            credential = self.find_credential(entry.source_id, entry.source_location)
            if credential is None:
                item.verdict = ItemVerdict.EVIDENCE_MISSING
                item.reject_reason = "归属凭据缺失，待补证"
                continue
            if not source.match_format(entry.raw_line):
                item.verdict = ItemVerdict.UNPARSEABLE
                item.reject_reason = "来源格式校验未通过"
                continue
            status, fields = rule.parse(entry.raw_line)
            if status != ParseResultStatus.OK or not fields:
                item.verdict = ItemVerdict.UNPARSEABLE
                item.reject_reason = "重新解析失败"
                entry.parse_status = status
                continue
            entry.parsed_fields = fields
            entry.parse_status = ParseResultStatus.OK
            entry.checksum = entry.compute_checksum()
            restored = extract_event_time(rule, source, fields)
            if restored is not None:
                entry.event_time = restored
            entry.host = credential.host_identity
            item.verdict = ItemVerdict.PASSED
            item.evidence_id = credential.credential_id
        return order

    # ---------- 获准放行 → 正式分类 + 写库存 ----------

    def approve_and_release(self, order_id: str, source: LogSourceConfig,
                            rule: ParseRule) -> ReleaseReceipt:
        """解除批次获准后切换到正式分类并写库存。

        - LINE：核验通过的行当班即可逐条放行，其余行继续隔离；
        - GROUP：必须整组核验通过，任一未核清则拒绝结清，未证实的行不会被
          包进正式结果；
        - 幂等：已结清/已放行的行再次调用（如回执超时重试）只落库一次。
        """
        order = self._require_order(order_id)
        if order.status == ReleaseOrderStatus.SETTLED:
            return ReleaseReceipt(
                order_id=order.order_id, released_line_keys=[],
                stored_event_count=0, already_settled=True,
            )
        if order.status != ReleaseOrderStatus.VERIFYING:
            raise QuarantineError("解除单尚未进入核验，不能获准放行")

        passed = [item for item in order.items if item.verdict == ItemVerdict.PASSED]
        if order.mode == ReleaseMode.GROUP and len(passed) != len(order.items):
            blocked = [
                item.entry.source_location for item in order.items
                if item.verdict != ItemVerdict.PASSED
            ]
            raise QuarantineError(
                f"按组结清须整组核清，以下行未通过：{'、'.join(blocked)}"
            )
        if not passed:
            # 部分放行后的回执超时重试：没有新增核验通过的行时幂等返回，
            # 不报错、不重复落库。
            if order.released_keys:
                return ReleaseReceipt(
                    order_id=order.order_id, released_line_keys=[],
                    stored_event_count=0, already_settled=False,
                )
            raise QuarantineError("没有核验通过的行可放行")

        releasable: list[LogEntry] = []
        released_keys: list[str] = []
        for item in passed:
            key = self._line_key(item.entry.source_id, item.entry.source_location)
            if key in order.released_keys:
                # 并发/超时重试：同一放行只落库一次。
                continue
            entry = item.entry
            entry.quarantined = False
            entry.release_order_id = order.order_id
            entry.release_evidence_id = item.evidence_id
            releasable.append(entry)
            released_keys.append(key)

        records: list[EventRecord] = self.pipeline.classify_events(releasable)
        stored = self.pipeline.store_events(records)

        now = datetime.now()
        for item in passed:
            key = self._line_key(item.entry.source_id, item.entry.source_location)
            if key in released_keys:
                item.verdict = ItemVerdict.RELEASED
                item.released_at = now
                order.released_keys.add(key)
                self._quarantine.pop(key, None)
        order.approved_at = now

        if order.mode == ReleaseMode.LINE:
            # 按原行核销：还有行处于待核验/未到达终态时单据保持核验中，
            # 全部到达终态（放行或拒绝类终态）才结清。
            terminal = {ItemVerdict.RELEASED, ItemVerdict.TAMPERED, ItemVerdict.UNPARSEABLE}
            if all(item.verdict in terminal for item in order.items):
                order.status = ReleaseOrderStatus.SETTLED
        else:
            order.status = ReleaseOrderStatus.SETTLED

        return ReleaseReceipt(
            order_id=order.order_id,
            released_line_keys=released_keys,
            stored_event_count=stored,
            already_settled=False,
        )

    # ---------- 排查消费：单机故障 vs 主机交接 ----------

    def consume_verified_events(self, host_identity: str) -> list[EventRecord]:
        """只定位单机的排查：可消费该机器已验证并已入库的错误事件。"""
        result: list[EventRecord] = []
        for records in self.pipeline.get_event_store().values():
            for record in records:
                if record.source_host == host_identity and record.event_type.category_tag == "error":
                    result.append(record)
        return result

    def build_handoff_evidence(self, order_id: str) -> dict[str, Any]:
        """主机交接调查：同一来源 A、B 原日志须相互印证。

        两行归属都核清（实际放行）后才能形成同源交接证据；任一行未证实则
        拒绝，不能把未证实的行包进正式结果。
        """
        order = self._require_order(order_id)
        if len(order.items) < 2:
            raise QuarantineError("主机交接证据至少需要两行同源日志相互印证")
        if any(item.verdict != ItemVerdict.RELEASED for item in order.items):
            pending = [
                item.entry.source_location for item in order.items
                if item.verdict != ItemVerdict.RELEASED
            ]
            raise QuarantineError(f"以下行归属尚未核清，不能形成交接证据：{'、'.join(pending)}")
        evidence = {
            "evidence_id": f"HAND-{order.order_id}",
            "order_id": order.order_id,
            "source_id": order.source_id,
            "line_locations": [item.entry.source_location for item in order.items],
            "host_identities": [item.entry.host for item in order.items],
            "evidence_ids": [item.evidence_id for item in order.items],
            "event_times": [item.entry.event_time.isoformat() if item.entry.event_time else ""
                            for item in order.items],
            "created_at": datetime.now().isoformat(),
        }
        self._handoff_evidence.append(evidence)
        return evidence

    def get_handoff_evidence(self) -> list[dict[str, Any]]:
        return list(self._handoff_evidence)

    # ---------- 查询 ----------

    def get_order(self, order_id: str) -> ReleaseOrder:
        return self._require_order(order_id)

    def list_orders(self) -> list[ReleaseOrder]:
        return list(self._orders.values())

    # ---------- 内部辅助 ----------

    def _require_order(self, order_id: str) -> ReleaseOrder:
        order = self._orders.get(order_id)
        if order is None:
            raise QuarantineError(f"解除单不存在：{order_id}")
        return order

    @staticmethod
    def _line_key(source_id: str, source_location: str) -> str:
        return f"{source_id}@{source_location}"


def make_quarantine_manager(pipeline: IngestPipeline | None = None) -> QuarantineManager:
    """工厂函数：创建绑定到采集管道的隔离解除管理器。"""
    return QuarantineManager(pipeline or IngestPipeline())
