import hashlib
import hmac
import logging
import signal
import time
import os
import asyncio
from dataclasses import dataclass, field
from multiprocessing import Event, Process, Queue, cpu_count
from typing import List, Optional, Dict, Tuple

# ============================================================
# Logging
# ============================================================

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CORE] :: %(message)s")
logger = logging.getLogger("ConsensusEngine_10_10_HPC_PERF_v2")

# ============================================================
# Core invariants / helpers
# ============================================================

def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


def _build_target_mask(target_bits: int) -> Tuple[int, int]:
    if target_bits == 0:
        return 0, 0
    full_bytes = target_bits // 8
    rem_bits = target_bits % 8
    if rem_bits == 0:
        return full_bytes, 0
    mask = ((0xFF << (8 - rem_bits)) & 0xFF)
    return full_bytes, mask


def _meets_target_branchless(digest: bytes, full_bytes: int, mask: int) -> bool:
    """
    Check that the first `target_bits` are zero.
    We keep the logic simple but avoid early returns on the prefix bytes.
    """
    acc = 0
    # accumulate OR over the full zero-bytes region
    for b in digest[:full_bytes]:
        acc |= b

    # if any non-zero in prefix, fail
    # this is a single branch on the accumulated value
    if acc != 0:
        return False

    # if no partial byte constraint, we're done
    if mask == 0:
        return True

    # check partial byte
    return (digest[full_bytes] & mask) == 0


# ============================================================
# Data structures
# ============================================================

@dataclass(slots=True, frozen=True)
class SemanticNode:
    node_id: str
    data: str
    target_bits: int
    hmac_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require(bool(self.node_id), "node_id must be non-empty")
        _require(isinstance(self.hmac_key, (bytes, bytearray)), "hmac_key must be bytes")
        _require(0 <= self.target_bits <= 256, "target_bits must be in [0, 256]")


@dataclass(slots=True, frozen=True)
class PoWTask:
    task_id: str
    context: str
    prefix: str
    target_bits: int
    max_nonce: int
    batch_size: int
    duration: float
    logical_clock: int
    global_seed: int
    challenge_salt: bytes
    max_solutions: int = 1

    full_bytes: int = field(init=False)
    mask: int = field(init=False)

    def __post_init__(self) -> None:
        _require(bool(self.task_id), "task_id must be non-empty")
        _require(bool(self.prefix), "prefix must be non-empty")
        _require(self.max_nonce > 0, "max_nonce must be > 0")
        _require(self.batch_size > 0, "batch_size must be > 0")
        _require(self.duration > 0.0, "duration must be > 0")
        _require(0 <= self.target_bits <= 256, "target_bits must be in [0, 256]")
        _require(isinstance(self.challenge_salt, (bytes, bytearray)), "challenge_salt must be bytes")
        _require(len(self.challenge_salt) > 0, "challenge_salt must be non-empty")
        _require(self.max_solutions > 0, "max_solutions must be > 0")

        full_bytes, mask = _build_target_mask(self.target_bits)
        object.__setattr__(self, "full_bytes", full_bytes)
        object.__setattr__(self, "mask", mask)


@dataclass(slots=True, frozen=True)
class PoWResult:
    node_id: str
    nonce: int
    hash_bytes: bytes
    task_id: str
    signature: str
    logical_clock: int
    global_seed: int

    @property
    def hash_hex(self) -> str:
        return self.hash_bytes.hex()

    def __post_init__(self) -> None:
        _require(bool(self.node_id), "node_id must be non-empty")
        _require(bool(self.task_id), "task_id must be non-empty")
        _require(isinstance(self.hash_bytes, (bytes, bytearray)), "hash_bytes must be bytes")
        _require(len(self.hash_bytes) == 32, "hash_bytes must be 32 bytes (blake2b-256)")
        _require(isinstance(self.signature, str) and len(self.signature) > 0, "signature must be non-empty hex string")


@dataclass(slots=True)
class EngineMetrics:
    total_hashes: int = 0
    total_solutions: int = 0
    start_time: float = 0.0
    end_time: float = 0.0

    @property
    def duration(self) -> float:
        return max(0.0, self.end_time - self.start_time)

    @property
    def hashes_per_second(self) -> float:
        if self.duration <= 0.0:
            return 0.0
        return self.total_hashes / self.duration


# ============================================================
# Hash / signature kernels
# ============================================================

def _compute_digest_base(
    prefix_b: bytes,
    node_id_b: bytes,
    seed_b: bytes,
    clock_b: bytes,
    salt_b: bytes,
) -> hashlib._blake2.blake2b:
    h = hashlib.blake2b(digest_size=32)
    h.update(b"POWv1")
    h.update(prefix_b)
    h.update(node_id_b)
    h.update(seed_b)
    h.update(clock_b)
    h.update(salt_b)
    return h


def _compute_digest_from_base(base: hashlib._blake2.blake2b, nonce: int) -> bytes:
    # On garde la sémantique exacte : base + nonce en big-endian
    h = base.copy()
    h.update(nonce.to_bytes(8, "big"))
    return h.digest()


def _sign_result(
    node: SemanticNode,
    task: PoWTask,
    nonce: int,
    digest: bytes,
) -> str:
    node_id_b = node.node_id.encode("utf-8")
    prefix_b = task.prefix.encode("utf-8")
    seed_b = task.global_seed.to_bytes(8, "big")
    clock_b = task.logical_clock.to_bytes(8, "big")
    salt_b = task.challenge_salt
    task_id_b = task.task_id.encode("utf-8")

    payload = (
        b"POW_SIGv1"
        + node_id_b
        + prefix_b
        + nonce.to_bytes(8, "big")
        + digest
        + seed_b
        + clock_b
        + salt_b
        + task_id_b
    )
    return hmac.new(node.hmac_key, payload, hashlib.sha256).hexdigest()


def _verify_result(
    result: PoWResult,
    node: SemanticNode,
    task: PoWTask,
) -> bool:
    if result.logical_clock != task.logical_clock:
        return False
    if result.global_seed != task.global_seed:
        return False
    if result.task_id != task.task_id:
        return False

    prefix_b = task.prefix.encode("utf-8")
    node_id_b = node.node_id.encode("utf-8")
    seed_b = task.global_seed.to_bytes(8, "big")
    clock_b = task.logical_clock.to_bytes(8, "big")
    salt_b = task.challenge_salt

    base = _compute_digest_base(
        prefix_b=prefix_b,
        node_id_b=node_id_b,
        seed_b=seed_b,
        clock_b=clock_b,
        salt_b=salt_b,
    )
    digest = _compute_digest_from_base(base, result.nonce)

    if digest != result.hash_bytes:
        return False
    if not _meets_target_branchless(digest, task.full_bytes, task.mask):
        return False

    expected_sig = _sign_result(node, task, result.nonce, digest)
    return hmac.compare_digest(expected_sig, result.signature)


# ============================================================
# Worker signals / affinity
# ============================================================

def _install_worker_signals() -> None:
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (ValueError, AttributeError):
        pass

    def _handle_term(signum, frame):
        logger.info(f"Worker received SIGTERM (signum={signum})")

    try:
        signal.signal(signal.SIGTERM, _handle_term)
    except (ValueError, AttributeError):
        pass


def _set_worker_affinity(worker_index: int) -> None:
    try:
        cpu_count_local = os.cpu_count() or 1
        target_cpu = worker_index % cpu_count_local
        if hasattr(os, "sched_setaffinity"):
            os.sched_setaffinity(0, {target_cpu})
    except Exception:
        pass


# ============================================================
# Deterministic node ordering
# ============================================================

def _deterministic_node_order(nodes: List[SemanticNode], seed: int) -> List[SemanticNode]:
    # On garde un ordre déterministe basé sur node_id + seed,
    # sans dépendre du hasard global.
    keyed = []
    for n in nodes:
        h = hashlib.blake2b(digest_size=16)
        h.update(seed.to_bytes(8, "big"))
        h.update(n.node_id.encode("utf-8"))
        keyed.append((h.digest(), n))
    keyed.sort(key=lambda x: x[0])
    return [n for _, n in keyed]


# ============================================================
# Worker loop (single-node kernel)
# ============================================================

def pow_worker(
    node: SemanticNode,
    task: PoWTask,
    abort_flag: Event,
    out_q: Queue,
    deadline: float,
    worker_index: int,
    metrics_q: Queue,
    deadline_check_interval_batches: int = 64,
) -> None:
    _install_worker_signals()
    _set_worker_affinity(worker_index)

    local_hashes = 0
    local_solutions = 0

    try:
        prefix_b = task.prefix.encode("utf-8")
        node_id_b = node.node_id.encode("utf-8")
        seed_b = task.global_seed.to_bytes(8, "big")
        clock_b = task.logical_clock.to_bytes(8, "big")
        salt_b = task.challenge_salt

        base = _compute_digest_base(
            prefix_b=prefix_b,
            node_id_b=node_id_b,
            seed_b=seed_b,
            clock_b=clock_b,
            salt_b=salt_b,
        )

        full_bytes = task.full_bytes
        mask = task.mask

        batch_index = 0

        for start_nonce in range(0, task.max_nonce, task.batch_size):
            if abort_flag.is_set():
                break

            # On ne checke le deadline que toutes N batches pour réduire l’overhead.
            if batch_index % deadline_check_interval_batches == 0:
                if time.perf_counter() >= deadline:
                    break

            end_nonce = min(start_nonce + task.batch_size, task.max_nonce)
            for nonce in range(start_nonce, end_nonce):
                if abort_flag.is_set():
                    break

                digest = _compute_digest_from_base(base, nonce)
                local_hashes += 1

                if _meets_target_branchless(digest, full_bytes, mask):
                    sig = _sign_result(node, task, nonce, digest)
                    try:
                        result = PoWResult(
                            node_id=node.node_id,
                            nonce=nonce,
                            hash_bytes=digest,
                            task_id=task.task_id,
                            signature=sig,
                            logical_clock=task.logical_clock,
                            global_seed=task.global_seed,
                        )
                    except Exception as e:
                        logger.error(f"Failed to construct PoWResult for node_id={node.node_id}: {e}")
                        abort_flag.set()
                        break

                    try:
                        out_q.put_nowait(result)
                    except Exception:
                        logger.warning(f"Result queue full, node_id={node.node_id}")

                    local_solutions += 1
                    if local_solutions >= task.max_solutions:
                        abort_flag.set()
                        break

            batch_index += 1

    except Exception as e:
        logger.error(f"Worker {node.node_id} failure: {e}")
    finally:
        try:
            metrics_q.put_nowait((local_hashes, local_solutions))
        except Exception:
            pass


# ============================================================
# Engine
# ============================================================

class PoWEngine:
    def __init__(
        self,
        max_workers: Optional[int] = None,
        queue_size: int = 64,
        sleep_interval: float = 0.001,
    ) -> None:
        self._max_workers = max_workers or cpu_count()
        self._queue_size = queue_size
        self._sleep_interval = sleep_interval

    def run_sync(self, task: PoWTask, nodes: List[SemanticNode]) -> Tuple[List[PoWResult], EngineMetrics]:
        abort_flag = Event()
        out_q: Queue = Queue(maxsize=self._queue_size)
        metrics_q: Queue = Queue(maxsize=self._max_workers * 2)
        procs: List[Process] = []

        metrics = EngineMetrics()
        metrics.start_time = time.perf_counter()
        deadline = metrics.start_time + task.duration

        ordered_nodes = _deterministic_node_order(nodes, task.global_seed)

        for idx, node in enumerate(ordered_nodes[: self._max_workers]):
            p = Process(
                target=pow_worker,
                args=(node, task, abort_flag, out_q, deadline, idx, metrics_q),
            )
            p.daemon = False
            p.start()
            procs.append(p)

        # Boucle d’orchestration minimaliste
        while not abort_flag.is_set():
            now = time.perf_counter()
            if now >= deadline:
                break
            time.sleep(self._sleep_interval)

        abort_flag.set()

        # Join rapide
        for p in procs:
            p.join(timeout=0.5)

        # Termination forcée si nécessaire
        for p in procs:
            if p.is_alive():
                try:
                    p.terminate()
                except Exception:
                    logger.warning(f"Failed to terminate process pid={p.pid}")
                p.join(timeout=0.5)

        raw_results: List[PoWResult] = []
        while not out_q.empty():
            try:
                raw_results.append(out_q.get_nowait())
            except Exception:
                break

        total_hashes = 0
        total_solutions = 0
        while not metrics_q.empty():
            try:
                h, s = metrics_q.get_nowait()
                total_hashes += h
                total_solutions += s
            except Exception:
                break

        metrics.total_hashes = total_hashes
        metrics.total_solutions = total_solutions
        metrics.end_time = time.perf_counter()

        verified_results: List[PoWResult] = []
        node_map: Dict[str, SemanticNode] = {n.node_id: n for n in nodes}

        for r in raw_results:
            node = node_map.get(r.node_id)
            if node is None:
                logger.warning(f"Result for unknown node_id={r.node_id}, discarded.")
                continue

            try:
                if _verify_result(r, node, task):
                    verified_results.append(r)
                else:
                    logger.warning(f"Invalid PoWResult from node_id={r.node_id}, discarded.")
            except Exception as e:
                logger.warning(f"Verification error for node_id={r.node_id}: {e}")

        unique: Dict[Tuple[str, str, int], PoWResult] = {}
        for r in verified_results:
            key = (r.task_id, r.node_id, r.nonce)
            if key not in unique:
                unique[key] = r

        final_results = list(unique.values())

        logger.info(
            f"PoWEngine completed: task_id={task.task_id}, "
            f"solutions={metrics.total_solutions}, "
            f"hashes={metrics.total_hashes}, "
            f"duration={metrics.duration:.6f}s, "
            f"hashes/s={metrics.hashes_per_second:.2f}"
        )

        return final_results, metrics

    async def run(self, task: PoWTask, nodes: List[SemanticNode]) -> Tuple[List[PoWResult], EngineMetrics]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.run_sync, task, nodes)
