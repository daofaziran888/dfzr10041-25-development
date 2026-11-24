"""测试：隔离日志解除流程（来源核验 → 重新解析 → 解除批次 → 分类入库）。

覆盖业务规则：
- 归属凭据缺失的行先隔离；apply_parse_rules 解析通过也不得交给 classify_events；
- 旁侧来源的普通行照常入库；
- 解除单状态 待补证 → 核验 → 结清；LINE 按原行核销 / GROUP 按组结清；
- 来源核验：位置不变但正文被替换单独拒绝，不能复用别的行的解析与凭据；
- 事件时间从原日志 + 来源时区还原，23:59+08:00 次日解除仍归原发生日分区；
- 单机排查可消费已验证错误事件；主机交接须 A、B 两行归属都核清；
- B 未通过前绝不正式分类；放行保留原日志位置与实际凭据；
- 回执超时/并发重试同一放行只落库一次；
- 解除批次实际计算错误或认证事件并落库。
"""
from __future__ import annotations

import contextlib
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.models import LogEntry, ParseResultStatus
from app.core.pipeline import (
    IngestPipeline, PRESET_LOG_SOURCES, PRESET_PARSE_RULES,
)
from app.core.quarantine import (
    ItemVerdict, QuarantineError, QuarantineManager, ReleaseMode,
    ReleaseOrderStatus, SourceCredential, make_quarantine_manager,
)


@contextlib.contextmanager
def raises(exc_type):
    """轻量断言：与现有测试风格一致，不依赖 pytest。"""
    try:
        yield
    except exc_type:
        return
    raise AssertionError(f"期望抛出 {exc_type.__name__} 但未抛出")


# ---------- 测试夹具与样本 ----------

APP_SOURCE = PRESET_LOG_SOURCES["app-backend"]
APP_RULE = PRESET_PARSE_RULES[1]
SYS_SOURCE = PRESET_LOG_SOURCES["sys-auth"]
SYS_RULE = PRESET_PARSE_RULES[2]
ACCESS_SOURCE = PRESET_LOG_SOURCES["access-web"]
ACCESS_RULE = PRESET_PARSE_RULES[0]

# 同一来源（backend-api 主机集群）的 A、B 两行，均为 ERROR，因归属凭据缺失被隔离。
LINE_A = ('2026-11-15 14:30:05.456 [http-nio-8080-exec-2] ERROR '
          'com.example.ParserEngine - 解析失败：regex mismatch at line 88')
LINE_B = ('2026-11-15 14:31:09.777 [http-nio-8081-exec-7] ERROR '
          'com.example.HandoffCoordinator - 主机交接校验中断，待归属凭据')
# 旁侧来源（Web 网关）的正常行，不应受隔离影响。
SIDE_LINE = ('192.168.1.20 - - [15/Nov/2026:14:35:00 +0800] '
             '"GET /api/ok HTTP/1.1" 200 100 "-" "Mozilla/5.0"')
# 跨日边界行：23:59+08:00，次日解除时分区仍须属于原发生日。
LINE_LATE = ('2026-11-15 23:59:59.999 [http-nio-8080-exec-9] ERROR '
             'com.example.ParserEngine - 跨日边界故障 at line 256')
# sys 认证隔离行：解除后应实际分类为认证事件。
LINE_AUTH = 'Nov 15 14:40:10 auth-server sshd[9001]: AUTH failure user=svc reason=token_revoked'


def _make_quarantined(manager: QuarantineManager, line: str,
                      source_id: str, location: str, line_no: int) -> LogEntry:
    """构造一条因归属凭据缺失被隔离的日志（格式真实有效）。"""
    entry = LogEntry(raw_line=line, line_number=line_no, source_id=source_id)
    return manager.quarantine_entry(entry, location)


class TestQuarantineBasics:
    """隔离纪律：解析通过也不分类，旁侧来源照常入库。"""

    def test_quarantined_lines_never_classified_even_if_parse_ok(self):
        pipeline = IngestPipeline()
        manager = make_quarantine_manager(pipeline)
        entry_a = _make_quarantined(manager, LINE_A, APP_SOURCE.source_id, "host-a:8080", 101)

        # apply_parse_rules 解析通过，但隔离标记必须保留，classify_events 不得消费。
        entries = pipeline.apply_parse_rules([entry_a], APP_RULE, APP_SOURCE)
        assert entries[0].parse_status == ParseResultStatus.OK
        assert entries[0].quarantined is True
        assert entries[0].event_time is not None
        assert pipeline.classify_events(entries) == []

    def test_side_source_normal_lines_still_ingested(self):
        pipeline = IngestPipeline()
        manager = make_quarantine_manager(pipeline)
        _make_quarantined(manager, LINE_A, APP_SOURCE.source_id, "host-a:8080", 101)
        _make_quarantined(manager, LINE_B, APP_SOURCE.source_id, "host-b:8081", 102)

        side_entries = pipeline.parse_raw_lines(ACCESS_SOURCE, [SIDE_LINE])
        side_parsed = pipeline.apply_parse_rules(side_entries, ACCESS_RULE, ACCESS_SOURCE)
        side_records = pipeline.classify_events(side_parsed)
        stored = pipeline.store_events(side_records)

        assert stored == 1
        all_records = [r for bucket in pipeline.get_event_store().values() for r in bucket]
        assert len(all_records) == 1
        assert all_records[0].release_order_id == ""  # 普通直采行无解除批次留痕

    def test_quarantine_preserves_original_location_and_snapshot(self):
        manager = make_quarantine_manager(IngestPipeline())
        entry = _make_quarantined(manager, LINE_A, APP_SOURCE.source_id, "host-a:8080", 101)
        assert entry.parse_status == ParseResultStatus.CREDENTIAL_MISSING
        assert entry.source_location == "host-a:8080"
        assert manager.get_quarantined(APP_SOURCE.source_id) == [entry]


class TestReleaseOrderLifecycle:
    """解除单状态流转与补证。"""

    def test_order_starts_pending_evidence_then_verifying(self):
        manager = make_quarantine_manager(IngestPipeline())
        _make_quarantined(manager, LINE_A, APP_SOURCE.source_id, "host-a:8080", 101)
        _make_quarantined(manager, LINE_B, APP_SOURCE.source_id, "host-b:8081", 102)

        order = manager.create_release_order(
            APP_SOURCE.source_id, ["host-a:8080", "host-b:8081"], ReleaseMode.LINE)
        assert order.status == ReleaseOrderStatus.PENDING_EVIDENCE

        manager.register_credential(SourceCredential(
            credential_id="CRED-A-1", source_id=APP_SOURCE.source_id,
            source_location="host-a:8080", host_identity="host-a"))
        manager.submit_evidence(order.order_id, "CRED-A-1")
        assert order.status == ReleaseOrderStatus.VERIFYING

    def test_cross_source_credential_rejected(self):
        manager = make_quarantine_manager(IngestPipeline())
        _make_quarantined(manager, LINE_A, APP_SOURCE.source_id, "host-a:8080", 101)
        order = manager.create_release_order(
            APP_SOURCE.source_id, ["host-a:8080"], ReleaseMode.LINE)
        manager.register_credential(SourceCredential(
            credential_id="CRED-X", source_id="LOG_-0001",
            source_location="host-a:8080", host_identity="host-a"))
        with raises(QuarantineError):
            manager.submit_evidence(order.order_id, "CRED-X")

    def test_verify_requires_verifying_state(self):
        manager = make_quarantine_manager(IngestPipeline())
        _make_quarantined(manager, LINE_A, APP_SOURCE.source_id, "host-a:8080", 101)
        order = manager.create_release_order(
            APP_SOURCE.source_id, ["host-a:8080"], ReleaseMode.LINE)
        with raises(QuarantineError):
            manager.verify_order(order.order_id, APP_SOURCE, APP_RULE)

    def test_creating_order_with_missing_line_raises(self):
        manager = make_quarantine_manager(IngestPipeline())
        with raises(QuarantineError):
            manager.create_release_order(
                APP_SOURCE.source_id, ["ghost:9999"], ReleaseMode.LINE)


class TestSourceVerificationAndReparse:
    """来源核验：凭据缺失、正文替换、重新解析失败均继续隔离。"""

    def test_missing_credential_line_kept_quarantined(self):
        pipeline = IngestPipeline()
        manager = make_quarantine_manager(pipeline)
        _make_quarantined(manager, LINE_A, APP_SOURCE.source_id, "host-a:8080", 101)
        _make_quarantined(manager, LINE_B, APP_SOURCE.source_id, "host-b:8081", 102)
        manager.register_credential(SourceCredential(
            credential_id="CRED-A-1", source_id=APP_SOURCE.source_id,
            source_location="host-a:8080", host_identity="host-a"))

        order = manager.create_release_order(
            APP_SOURCE.source_id, ["host-a:8080", "host-b:8081"], ReleaseMode.LINE)
        manager.submit_evidence(order.order_id, "CRED-A-1")
        manager.verify_order(order.order_id, APP_SOURCE, APP_RULE)

        verdicts = {item.entry.source_location: item.verdict for item in order.items}
        assert verdicts["host-a:8080"] == ItemVerdict.PASSED
        assert verdicts["host-b:8081"] == ItemVerdict.EVIDENCE_MISSING
        # B 仍然隔离，凭据缺失不能进入正式分类。
        b_entry = next(e for e in manager.get_quarantined(APP_SOURCE.source_id)
                       if e.source_location == "host-b:8081")
        assert b_entry.quarantined is True
        a_entry = next(e for e in manager.get_quarantined(APP_SOURCE.source_id)
                       if e.source_location == "host-a:8080")
        assert a_entry.quarantined is True

    def test_tampered_body_rejected_even_with_valid_credential(self):
        pipeline = IngestPipeline()
        manager = make_quarantine_manager(pipeline)
        entry_a = _make_quarantined(manager, LINE_A, APP_SOURCE.source_id, "host-a:8080", 101)
        manager.register_credential(SourceCredential(
            credential_id="CRED-A-1", source_id=APP_SOURCE.source_id,
            source_location="host-a:8080", host_identity="host-a"))

        order = manager.create_release_order(
            APP_SOURCE.source_id, ["host-a:8080"], ReleaseMode.LINE)
        manager.submit_evidence(order.order_id, "CRED-A-1")

        # 来源位置没变，但原行正文被另一份内容替换。
        entry_a.raw_line = LINE_A.replace("line 88", "line 999-injected")
        manager.verify_order(order.order_id, APP_SOURCE, APP_RULE)

        item = order.items[0]
        assert item.verdict == ItemVerdict.TAMPERED
        assert "替换" in item.reject_reason
        assert entry_a.quarantined is True
        # 凭据没有被复用为放行证据。
        assert item.evidence_id == ""
        with raises(QuarantineError):
            manager.approve_and_release(order.order_id, APP_SOURCE, APP_RULE)

    def test_tampered_line_cannot_reuse_other_lines_parse_and_credential(self):
        """同单 A 成功解析放行、B 正文被替换：B 不能复用 A 的解析与凭据。"""
        pipeline = IngestPipeline()
        manager = make_quarantine_manager(pipeline)
        entry_a = _make_quarantined(manager, LINE_A, APP_SOURCE.source_id, "host-a:8080", 101)
        entry_b = _make_quarantined(manager, LINE_B, APP_SOURCE.source_id, "host-b:8081", 102)
        manager.register_credential(SourceCredential(
            credential_id="CRED-A-1", source_id=APP_SOURCE.source_id,
            source_location="host-a:8080", host_identity="host-a"))

        order = manager.create_release_order(
            APP_SOURCE.source_id, ["host-a:8080", "host-b:8081"], ReleaseMode.LINE)
        manager.submit_evidence(order.order_id, "CRED-A-1")
        # B 的位置没变、正文被偷换。
        entry_b.raw_line = LINE_B.replace("待归属凭据", "注入的伪造内容")
        manager.verify_order(order.order_id, APP_SOURCE, APP_RULE)
        manager.approve_and_release(order.order_id, APP_SOURCE, APP_RULE)

        item_b = next(i for i in order.items if i.entry.source_location == "host-b:8081")
        assert item_b.verdict == ItemVerdict.TAMPERED
        assert item_b.evidence_id == ""  # A 的 CRED-A-1 没有被 B 复用
        assert entry_b.quarantined is True
        stored = [r for bucket in pipeline.get_event_store().values() for r in bucket]
        assert [r.source_host for r in stored] == ["host-a"]  # 只有 A 入库

    def test_unparseable_line_stays_quarantined(self):
        pipeline = IngestPipeline()
        manager = make_quarantine_manager(pipeline)
        # 隔离时为合法行；核验前从来源位置重新拉取到一份无法解析的正文，
        # 真实格式校验与正则解析都须把它挡在隔离区。
        entry = LogEntry(raw_line=LINE_A, line_number=101, source_id=APP_SOURCE.source_id)
        manager.quarantine_entry(entry, "host-a:8080")
        manager.register_credential(SourceCredential(
            credential_id="CRED-A-1", source_id=APP_SOURCE.source_id,
            source_location="host-a:8080", host_identity="host-a"))
        order = manager.create_release_order(
            APP_SOURCE.source_id, ["host-a:8080"], ReleaseMode.LINE)
        manager.submit_evidence(order.order_id, "CRED-A-1")

        manager.refresh_from_source(
            APP_SOURCE.source_id, "host-a:8080", "#### not an app log any more ####")
        manager.verify_order(order.order_id, APP_SOURCE, APP_RULE)
        assert order.items[0].verdict == ItemVerdict.UNPARSEABLE
        assert entry.quarantined is True
        with raises(QuarantineError):
            manager.approve_and_release(order.order_id, APP_SOURCE, APP_RULE)


class TestLineModeRelease:
    """按原行核销：A 当班即可入库，B 等待补证。"""

    def test_line_mode_releases_a_without_b(self):
        pipeline = IngestPipeline()
        manager = make_quarantine_manager(pipeline)
        _make_quarantined(manager, LINE_A, APP_SOURCE.source_id, "host-a:8080", 101)
        _make_quarantined(manager, LINE_B, APP_SOURCE.source_id, "host-b:8081", 102)
        manager.register_credential(SourceCredential(
            credential_id="CRED-A-1", source_id=APP_SOURCE.source_id,
            source_location="host-a:8080", host_identity="host-a"))

        order = manager.create_release_order(
            APP_SOURCE.source_id, ["host-a:8080", "host-b:8081"], ReleaseMode.LINE)
        manager.submit_evidence(order.order_id, "CRED-A-1")
        manager.verify_order(order.order_id, APP_SOURCE, APP_RULE)
        receipt = manager.approve_and_release(order.order_id, APP_SOURCE, APP_RULE)

        # A 当班进入错误事件库；B 未通过，绝不能正式分类。
        assert receipt.stored_event_count == 1
        assert receipt.released_line_keys == ["LOG_-0002@host-a:8080"]
        stored = [r for bucket in pipeline.get_event_store().values() for r in bucket]
        assert len(stored) == 1
        record = stored[0]
        assert record.event_type.type_id == "EVEN-0002"  # 错误事件
        assert record.source_host == "host-a"
        # 留痕：原日志位置与解除时实际使用的凭据。
        assert record.source_location == "host-a:8080"
        assert record.release_evidence_id == "CRED-A-1"
        assert record.release_order_id == order.order_id

        # B 仍在隔离区，单据未结清（处于核验中，等 B 补证）。
        assert [e.source_location for e in manager.get_quarantined()] == ["host-b:8081"]
        assert order.status == ReleaseOrderStatus.VERIFYING
        assert order.items[1].verdict == ItemVerdict.EVIDENCE_MISSING

    def test_line_mode_settles_after_b_evidence_completed(self):
        pipeline = IngestPipeline()
        manager = make_quarantine_manager(pipeline)
        _make_quarantined(manager, LINE_A, APP_SOURCE.source_id, "host-a:8080", 101)
        _make_quarantined(manager, LINE_B, APP_SOURCE.source_id, "host-b:8081", 102)
        manager.register_credential(SourceCredential(
            credential_id="CRED-A-1", source_id=APP_SOURCE.source_id,
            source_location="host-a:8080", host_identity="host-a"))

        order = manager.create_release_order(
            APP_SOURCE.source_id, ["host-a:8080", "host-b:8081"], ReleaseMode.LINE)
        manager.submit_evidence(order.order_id, "CRED-A-1")
        manager.verify_order(order.order_id, APP_SOURCE, APP_RULE)
        manager.approve_and_release(order.order_id, APP_SOURCE, APP_RULE)

        # 后续经独立验证补报 B 的凭据，再核验放行；单据此时才结清。
        manager.register_credential(SourceCredential(
            credential_id="CRED-B-1", source_id=APP_SOURCE.source_id,
            source_location="host-b:8081", host_identity="host-b"))
        manager.verify_order(order.order_id, APP_SOURCE, APP_RULE)
        receipt = manager.approve_and_release(order.order_id, APP_SOURCE, APP_RULE)

        assert receipt.stored_event_count == 1
        assert order.status == ReleaseOrderStatus.SETTLED
        stored = [r for bucket in pipeline.get_event_store().values() for r in bucket]
        assert {r.source_host for r in stored} == {"host-a", "host-b"}
        assert manager.get_quarantined() == []

    def test_idempotent_retry_after_receipt_timeout(self):
        pipeline = IngestPipeline()
        manager = make_quarantine_manager(pipeline)
        _make_quarantined(manager, LINE_A, APP_SOURCE.source_id, "host-a:8080", 101)
        manager.register_credential(SourceCredential(
            credential_id="CRED-A-1", source_id=APP_SOURCE.source_id,
            source_location="host-a:8080", host_identity="host-a"))
        order = manager.create_release_order(
            APP_SOURCE.source_id, ["host-a:8080"], ReleaseMode.LINE)
        manager.submit_evidence(order.order_id, "CRED-A-1")
        manager.verify_order(order.order_id, APP_SOURCE, APP_RULE)

        # 第一次放行：模拟入库完成但回执超时，客户端重试。
        first = manager.approve_and_release(order.order_id, APP_SOURCE, APP_RULE)
        retry = manager.approve_and_release(order.order_id, APP_SOURCE, APP_RULE)

        assert first.stored_event_count == 1
        assert retry.stored_event_count == 0
        assert retry.already_settled is True
        stored = [r for bucket in pipeline.get_event_store().values() for r in bucket]
        assert len(stored) == 1  # 同一放行只落库一次


class TestGroupModeRelease:
    """按组结清：A、B 都验过才一起分类入库。"""

    def test_group_blocks_until_both_verified(self):
        pipeline = IngestPipeline()
        manager = make_quarantine_manager(pipeline)
        _make_quarantined(manager, LINE_A, APP_SOURCE.source_id, "host-a:8080", 101)
        _make_quarantined(manager, LINE_B, APP_SOURCE.source_id, "host-b:8081", 102)
        manager.register_credential(SourceCredential(
            credential_id="CRED-A-1", source_id=APP_SOURCE.source_id,
            source_location="host-a:8080", host_identity="host-a"))

        order = manager.create_release_order(
            APP_SOURCE.source_id, ["host-a:8080", "host-b:8081"], ReleaseMode.GROUP)
        manager.submit_evidence(order.order_id, "CRED-A-1")
        manager.verify_order(order.order_id, APP_SOURCE, APP_RULE)

        # A 已证实、B 未证实时，按组结清拒绝放行，A 也不能提前入库。
        with raises(QuarantineError):
            manager.approve_and_release(order.order_id, APP_SOURCE, APP_RULE)
        assert pipeline.get_event_store() == {}
        assert all(e.quarantined for e in manager.get_quarantined())

        manager.register_credential(SourceCredential(
            credential_id="CRED-B-1", source_id=APP_SOURCE.source_id,
            source_location="host-b:8081", host_identity="host-b"))
        manager.verify_order(order.order_id, APP_SOURCE, APP_RULE)
        receipt = manager.approve_and_release(order.order_id, APP_SOURCE, APP_RULE)

        assert receipt.stored_event_count == 2
        assert order.status == ReleaseOrderStatus.SETTLED
        stored = [r for bucket in pipeline.get_event_store().values() for r in bucket]
        assert {r.source_host for r in stored} == {"host-a", "host-b"}

    def test_group_retry_is_idempotent(self):
        pipeline = IngestPipeline()
        manager = make_quarantine_manager(pipeline)
        _make_quarantined(manager, LINE_A, APP_SOURCE.source_id, "host-a:8080", 101)
        _make_quarantined(manager, LINE_B, APP_SOURCE.source_id, "host-b:8081", 102)
        for loc, host, cid in [("host-a:8080", "host-a", "CRED-A-1"),
                               ("host-b:8081", "host-b", "CRED-B-1")]:
            manager.register_credential(SourceCredential(
                credential_id=cid, source_id=APP_SOURCE.source_id,
                source_location=loc, host_identity=host))
        order = manager.create_release_order(
            APP_SOURCE.source_id, ["host-a:8080", "host-b:8081"], ReleaseMode.GROUP)
        manager.submit_evidence(order.order_id, "CRED-A-1")
        manager.verify_order(order.order_id, APP_SOURCE, APP_RULE)
        manager.approve_and_release(order.order_id, APP_SOURCE, APP_RULE)
        retry = manager.approve_and_release(order.order_id, APP_SOURCE, APP_RULE)

        assert retry.already_settled is True
        stored = [r for bucket in pipeline.get_event_store().values() for r in bucket]
        assert len(stored) == 2


class TestInvestigationConsumption:
    """单机故障排查 vs 主机交接调查。"""

    def _line_mode_setup(self) -> tuple[IngestPipeline, QuarantineManager, str]:
        pipeline = IngestPipeline()
        manager = make_quarantine_manager(pipeline)
        _make_quarantined(manager, LINE_A, APP_SOURCE.source_id, "host-a:8080", 101)
        _make_quarantined(manager, LINE_B, APP_SOURCE.source_id, "host-b:8081", 102)
        manager.register_credential(SourceCredential(
            credential_id="CRED-A-1", source_id=APP_SOURCE.source_id,
            source_location="host-a:8080", host_identity="host-a"))
        order = manager.create_release_order(
            APP_SOURCE.source_id, ["host-a:8080", "host-b:8081"], ReleaseMode.LINE)
        manager.submit_evidence(order.order_id, "CRED-A-1")
        manager.verify_order(order.order_id, APP_SOURCE, APP_RULE)
        manager.approve_and_release(order.order_id, APP_SOURCE, APP_RULE)
        return pipeline, manager, order.order_id

    def test_single_machine_investigation_consumes_verified_error(self):
        pipeline, manager, _ = self._line_mode_setup()
        # 只定位 A 单机故障的排查：可消费 A 已验证的错误事件。
        host_a_events = manager.consume_verified_events("host-a")
        assert len(host_a_events) == 1
        assert host_a_events[0].event_type.category_tag == "error"
        # B 尚未验证，查不到任何 B 的正式事件。
        assert manager.consume_verified_events("host-b") == []

    def test_handoff_evidence_requires_both_lines_verified(self):
        pipeline, manager, order_id = self._line_mode_setup()
        # 主机交接调查须 A、B 相互印证；B 未证实不能形成同源交接证据。
        with raises(QuarantineError):
            manager.build_handoff_evidence(order_id)
        assert manager.get_handoff_evidence() == []

        manager.register_credential(SourceCredential(
            credential_id="CRED-B-1", source_id=APP_SOURCE.source_id,
            source_location="host-b:8081", host_identity="host-b"))
        manager.verify_order(order_id, APP_SOURCE, APP_RULE)
        manager.approve_and_release(order_id, APP_SOURCE, APP_RULE)

        evidence = manager.build_handoff_evidence(order_id)
        assert evidence["source_id"] == APP_SOURCE.source_id
        assert set(evidence["line_locations"]) == {"host-a:8080", "host-b:8081"}
        assert set(evidence["host_identities"]) == {"host-a", "host-b"}
        assert set(evidence["evidence_ids"]) == {"CRED-A-1", "CRED-B-1"}


class TestEventTimeRestoration:
    """事件时间还原：用原日志 + 来源时区，不用放行当前时间。"""

    def test_late_night_line_keeps_original_day_partition(self):
        pipeline = IngestPipeline()
        manager = make_quarantine_manager(pipeline)
        _make_quarantined(manager, LINE_LATE, APP_SOURCE.source_id, "host-a:8080", 201)
        manager.register_credential(SourceCredential(
            credential_id="CRED-A-1", source_id=APP_SOURCE.source_id,
            source_location="host-a:8080", host_identity="host-a"))
        order = manager.create_release_order(
            APP_SOURCE.source_id, ["host-a:8080"], ReleaseMode.LINE)
        manager.submit_evidence(order.order_id, "CRED-A-1")
        manager.verify_order(order.order_id, APP_SOURCE, APP_RULE)
        manager.approve_and_release(order.order_id, APP_SOURCE, APP_RULE)

        stored = [r for bucket in pipeline.get_event_store().values() for r in bucket]
        assert len(stored) == 1
        record = stored[0]
        # 即使次日解除，23:59+08:00 的事件仍属于原发生日 20261115 的分区。
        assert record.store_partition == "20261115"
        assert record.event_time == datetime(2026, 11, 15, 23, 59, 59, 999000,
                                              tzinfo=record.event_time.tzinfo)
        assert str(record.event_time.utcoffset()) == "8:00:00"

    def test_sys_auth_line_classified_as_auth_event_on_release(self):
        pipeline = IngestPipeline()
        manager = make_quarantine_manager(pipeline)
        _make_quarantined(manager, LINE_AUTH, SYS_SOURCE.source_id, "auth-server:sshd", 301)
        manager.register_credential(SourceCredential(
            credential_id="CRED-SYS-1", source_id=SYS_SOURCE.source_id,
            source_location="auth-server:sshd", host_identity="auth-server"))
        order = manager.create_release_order(
            SYS_SOURCE.source_id, ["auth-server:sshd"], ReleaseMode.LINE)
        manager.submit_evidence(order.order_id, "CRED-SYS-1")
        manager.verify_order(order.order_id, SYS_SOURCE, SYS_RULE)
        receipt = manager.approve_and_release(order.order_id, SYS_SOURCE, SYS_RULE)

        assert receipt.stored_event_count == 1
        stored = [r for bucket in pipeline.get_event_store().values() for r in bucket]
        record = stored[0]
        # 解除批次实际计算出认证事件并落库。
        assert record.event_type.type_id == "EVEN-0003"
        assert record.event_type.category_tag == "auth"
        # sys 时间戳没有年份，按来源时区补当前年，事件时间不是放行当前时间。
        assert record.event_time.month == 11 and record.event_time.day == 15
        assert record.event_time.hour == 14 and record.event_time.minute == 40
        assert str(record.event_time.utcoffset()) == "8:00:00"
        assert record.store_partition == f"{datetime.now().year}1115"


class TestMixedTrafficInventory:
    """端到端：普通行与隔离行走真实格式校验/分类，补 A 凭据，模拟回执超时，核库存与 B。"""

    def test_full_round_inventory_and_pending_b(self):
        pipeline = IngestPipeline()
        manager = make_quarantine_manager(pipeline)

        # 1) 普通行（同来源正常 INFO 行 + 旁侧来源 web 行）走真实采集链路。
        normal_app = ('2026-11-15 09:00:00.001 [http-nio-8080-exec-1] INFO  '
                      'com.example.IngestController - 常规心跳')
        app_entries = pipeline.parse_raw_lines(APP_SOURCE, [normal_app])
        web_entries = pipeline.parse_raw_lines(ACCESS_SOURCE, [SIDE_LINE])
        pipeline.apply_parse_rules(app_entries, APP_RULE, APP_SOURCE)
        pipeline.apply_parse_rules(web_entries, ACCESS_RULE, ACCESS_SOURCE)
        normal_records = pipeline.classify_events(app_entries + web_entries)
        pipeline.store_events(normal_records)

        # 2) A、B 因归属凭据缺失被隔离。
        _make_quarantined(manager, LINE_A, APP_SOURCE.source_id, "host-a:8080", 101)
        _make_quarantined(manager, LINE_B, APP_SOURCE.source_id, "host-b:8081", 102)

        # 3) 补入 A 的有效凭据，核验后放行（LINE 模式）。
        manager.register_credential(SourceCredential(
            credential_id="CRED-A-1", source_id=APP_SOURCE.source_id,
            source_location="host-a:8080", host_identity="host-a"))
        order = manager.create_release_order(
            APP_SOURCE.source_id, ["host-a:8080", "host-b:8081"], ReleaseMode.LINE)
        manager.submit_evidence(order.order_id, "CRED-A-1")
        manager.verify_order(order.order_id, APP_SOURCE, APP_RULE)
        receipt = manager.approve_and_release(order.order_id, APP_SOURCE, APP_RULE)
        assert receipt.stored_event_count == 1

        # 4) 模拟入库完成但回执超时：重试同一放行，库存不重复增加。
        retry = manager.approve_and_release(order.order_id, APP_SOURCE, APP_RULE)
        assert retry.stored_event_count == 0

        # 5) 核对本轮库存：INFO 普通行 + 旁侧 web 行 + A 错误事件，共 3 条。
        stored = [r for bucket in pipeline.get_event_store().values() for r in bucket]
        assert len(stored) == 3
        hosts = sorted(r.source_host for r in stored)
        assert "host-a" in hosts
        a_record = next(r for r in stored if r.source_host == "host-a")
        assert a_record.event_type.category_tag == "error"
        assert a_record.release_evidence_id == "CRED-A-1"
        assert a_record.source_location == "host-a:8080"

        # 6) B 仍在隔离，且绝不存在 B 的正式分类事件。
        quarantined = manager.get_quarantined(APP_SOURCE.source_id)
        assert [e.source_location for e in quarantined] == ["host-b:8081"]
        assert all(r.source_host != "host-b" for r in stored)

        # 7) B 后续经独立验证才能放出。
        manager.register_credential(SourceCredential(
            credential_id="CRED-B-1", source_id=APP_SOURCE.source_id,
            source_location="host-b:8081", host_identity="host-b"))
        manager.verify_order(order.order_id, APP_SOURCE, APP_RULE)
        final_receipt = manager.approve_and_release(order.order_id, APP_SOURCE, APP_RULE)
        assert final_receipt.stored_event_count == 1
        assert order.status == ReleaseOrderStatus.SETTLED
        stored_after = [r for bucket in pipeline.get_event_store().values() for r in bucket]
        assert len(stored_after) == 4
        assert {r.source_host for r in stored_after} >= {"host-a", "host-b"}


# ---------- 运行入口（确定性测试，不依赖 pytest 也可直接执行） ----------

if __name__ == "__main__":
    import traceback

    test_classes = [
        TestQuarantineBasics, TestReleaseOrderLifecycle,
        TestSourceVerificationAndReparse, TestLineModeRelease,
        TestGroupModeRelease, TestInvestigationConsumption,
        TestEventTimeRestoration, TestMixedTrafficInventory,
    ]
    passed = failed = 0
    for cls in test_classes:
        for name in sorted(vars(cls)):
            if not name.startswith("test_"):
                continue
            try:
                getattr(cls, name)(cls())
                passed += 1
                print(f"  PASS  test_quarantine_release: {cls.__name__}.{name}")
            except Exception:
                failed += 1
                print(f"  FAIL  test_quarantine_release: {cls.__name__}.{name}")
                traceback.print_exc()
    print(f"\ntest_quarantine_release: {passed} passed, {failed} failed, {passed + failed} total")
    sys.exit(1 if failed else 0)
