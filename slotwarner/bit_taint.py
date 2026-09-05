from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


def width_mask(width: int) -> int:
    if width <= 0:
        return 0
    return (1 << int(width)) - 1


def range_mask(start: int, end: int, *, width: int = 256) -> int:
    start = max(0, int(start))
    end = min(int(width) - 1, int(end))
    if end < start:
        return 0
    return ((1 << (end - start + 1)) - 1) << start


def mask_intervals(mask: int, *, width: int = 256) -> list[tuple[int, int]]:
    mask &= width_mask(width)
    out: list[tuple[int, int]] = []
    i = 0
    while i < width:
        if not ((mask >> i) & 1):
            i += 1
            continue
        start = i
        while i + 1 < width and ((mask >> (i + 1)) & 1):
            i += 1
        out.append((start, i))
        i += 1
    return out


def popcount(mask: int) -> int:
    return int(mask).bit_count()


def intervals_mask(intervals: Iterable[tuple[int, int] | list[int]], *, width: int = 256) -> int:
    out = 0
    for pair in intervals:
        if len(pair) != 2:
            raise ValueError(f"interval must have two elements: {pair}")
        out |= range_mask(int(pair[0]), int(pair[1]), width=width)
    return out & width_mask(width)


@dataclass(frozen=True)
class BitInfluence:
    """Bit-granular dependency mask for one abstract value.

    ``mask`` marks result bits that depend on one or more tracked external/state sources.
    ``sources`` is explanatory provenance only; exact per-source masks can be carried in
    ``source_masks`` when known.
    """

    width: int = 256
    mask: int = 0
    source_masks: dict[str, int] = field(default_factory=dict)
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "width", int(self.width))
        object.__setattr__(self, "mask", int(self.mask) & width_mask(self.width))
        cleaned = {str(k): int(v) & width_mask(self.width) for k, v in self.source_masks.items() if int(v)}
        object.__setattr__(self, "source_masks", cleaned)

    @classmethod
    def source(cls, name: str, start: int, end: int, *, width: int = 256) -> "BitInfluence":
        m = range_mask(start, end, width=width)
        return cls(width=width, mask=m, source_masks={name: m})

    @property
    def affected_bits(self) -> int:
        return popcount(self.mask)

    @property
    def intervals(self) -> list[tuple[int, int]]:
        return mask_intervals(self.mask, width=self.width)

    def as_dict(self) -> dict[str, Any]:
        return {
            "width": self.width,
            "mask_hex": hex(self.mask),
            "affected_bits": self.affected_bits,
            "intervals": [[a, b] for a, b in self.intervals],
            "source_masks": {k: hex(v) for k, v in sorted(self.source_masks.items())},
            "notes": list(self.notes),
        }


def _merge_sources(values: Iterable[BitInfluence], result_masks: list[int] | None = None, *, width: int = 256) -> dict[str, int]:
    out: dict[str, int] = {}
    vals = list(values)
    for idx, v in enumerate(vals):
        for name, m in v.source_masks.items():
            mm = m
            if result_masks is not None:
                mm &= result_masks[idx]
            out[name] = (out.get(name, 0) | mm) & width_mask(width)
    return {k: v for k, v in out.items() if v}


def bitwise_or(a: BitInfluence, b: BitInfluence) -> BitInfluence:
    width = max(a.width, b.width)
    m = (a.mask | b.mask) & width_mask(width)
    notes = tuple(dict.fromkeys(tuple(a.notes) + tuple(b.notes)))
    return BitInfluence(width=width, mask=m, source_masks=_merge_sources([a, b], width=width), notes=notes)


def bitwise_xor(a: BitInfluence, b: BitInfluence) -> BitInfluence:
    # Dependency is union: either operand can influence a result bit.
    return bitwise_or(a, b)


def and_constant(value: BitInfluence, constant: int) -> BitInfluence:
    keep = int(constant) & width_mask(value.width)
    m = value.mask & keep
    src = {k: v & keep for k, v in value.source_masks.items() if v & keep}
    return BitInfluence(width=value.width, mask=m, source_masks=src, notes=value.notes + ("and_constant",))


def or_constant(value: BitInfluence, constant: int) -> BitInfluence:
    # Bits forced to 1 by the constant no longer depend on the operand.
    forced = int(constant) & width_mask(value.width)
    keep = width_mask(value.width) ^ forced
    m = value.mask & keep
    src = {k: v & keep for k, v in value.source_masks.items() if v & keep}
    return BitInfluence(width=value.width, mask=m, source_masks=src, notes=value.notes + ("or_constant",))


def shift_left(value: BitInfluence, amount: int) -> BitInfluence:
    amount = max(0, int(amount))
    m = (value.mask << amount) & width_mask(value.width)
    src = {k: (v << amount) & width_mask(value.width) for k, v in value.source_masks.items()}
    return BitInfluence(width=value.width, mask=m, source_masks=src, notes=value.notes + (f"shl:{amount}",))


def shift_right(value: BitInfluence, amount: int) -> BitInfluence:
    amount = max(0, int(amount))
    m = value.mask >> amount
    src = {k: v >> amount for k, v in value.source_masks.items()}
    return BitInfluence(width=value.width, mask=m, source_masks=src, notes=value.notes + (f"shr:{amount}",))


def extract_bits(value: BitInfluence, start: int, length: int, *, result_width: int | None = None) -> BitInfluence:
    """Extract ``length`` bits beginning at ``start`` and right-align them."""
    start = max(0, int(start)); length = max(0, int(length))
    out_width = int(result_width or max(1, length))
    keep = range_mask(start, start + length - 1, width=value.width)
    m = ((value.mask & keep) >> start) & width_mask(out_width)
    src = {k: ((v & keep) >> start) & width_mask(out_width) for k, v in value.source_masks.items()}
    return BitInfluence(width=out_width, mask=m, source_masks=src, notes=value.notes + (f"extract:{start}:{length}",))


def insert_bits(base: BitInfluence, inserted: BitInfluence, start: int, length: int) -> BitInfluence:
    """Model bitfield replacement into ``base``; overwritten base dependencies are removed."""
    start = max(0, int(start)); length = max(0, int(length))
    width = base.width
    dest = range_mask(start, start + length - 1, width=width)
    base_mask = base.mask & ~dest & width_mask(width)
    ins_mask = (inserted.mask & width_mask(length)) << start
    mask = (base_mask | ins_mask) & width_mask(width)
    src: dict[str, int] = {}
    for k, m in base.source_masks.items():
        mm = m & ~dest & width_mask(width)
        if mm: src[k] = src.get(k, 0) | mm
    for k, m in inserted.source_masks.items():
        mm = (m & width_mask(length)) << start
        if mm: src[k] = src.get(k, 0) | mm
    return BitInfluence(width=width, mask=mask, source_masks=src, notes=base.notes + inserted.notes + (f"insert:{start}:{length}",))


def add_sub_conservative(a: BitInfluence, b: BitInfluence, *, op: str = "add") -> BitInfluence:
    """Conservative bit dependency for ADD/SUB carry/borrow propagation.

    If any operand bit ``k`` is influenced, bits k..MSB may depend on it through carry/borrow.
    This intentionally over-approximates rather than silently missing high-bit propagation.
    """
    width = max(a.width, b.width)
    union = (a.mask | b.mask) & width_mask(width)
    if not union:
        return BitInfluence(width=width)
    lowest = (union & -union).bit_length() - 1
    result_mask = range_mask(lowest, width - 1, width=width)
    src: dict[str, int] = {}
    for v in (a, b):
        for name, sm in v.source_masks.items():
            if not sm:
                continue
            k = (sm & -sm).bit_length() - 1
            src[name] = src.get(name, 0) | range_mask(k, width - 1, width=width)
    return BitInfluence(width=width, mask=result_mask, source_masks=src, notes=(f"{op}_carry_conservative",))


def nonlinear_full_dependency(*values: BitInfluence, width: int = 256, label: str = "nonlinear") -> BitInfluence:
    if not any(v.mask for v in values):
        return BitInfluence(width=width)
    full = width_mask(width)
    names = {name for v in values for name in v.source_masks}
    return BitInfluence(width=width, mask=full, source_masks={name: full for name in names}, notes=(label,))


def project_relative_mask_to_footprint(footprint: dict[str, Any], relative_mask: int) -> int:
    """Translate a leaf-relative mask into the 0..255 bit coordinates of its storage slot."""
    width = int(footprint["width_bits"])
    start = int(footprint["slot_bit_start"])
    return (int(relative_mask) & width_mask(width)) << start


def project_logic_taint_to_proxy(
    logic_footprint: dict[str, Any],
    relative_taint_mask: int,
    proxy_footprints: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Project tainted bits of one logic leaf onto proxy leaves in the same physical slot."""
    slot = int(logic_footprint["slot"])
    physical_mask = project_relative_mask_to_footprint(logic_footprint, relative_taint_mask) & width_mask(256)
    out: list[dict[str, Any]] = []
    for pf in proxy_footprints:
        if pf.get("kind") != "direct" or int(pf.get("slot", -1)) != slot:
            continue
        pstart = int(pf["slot_bit_start"]); pend = int(pf["slot_bit_end"])
        pmask = range_mask(pstart, pend, width=256)
        hit = physical_mask & pmask
        if not hit:
            continue
        relative_proxy = hit >> pstart
        pwidth = int(pf["width_bits"])
        out.append({
            "slot": slot,
            "logic_path": logic_footprint.get("path"),
            "logic_physical_taint_intervals": [[a, b] for a, b in mask_intervals(physical_mask, width=256)],
            "proxy_path": pf.get("path"),
            "proxy_variable_width_bits": pwidth,
            "proxy_affected_bits": popcount(relative_proxy),
            "proxy_coverage_ratio": popcount(relative_proxy) / pwidth if pwidth else 0.0,
            "proxy_relative_taint_mask_hex": hex(relative_proxy),
            "proxy_relative_taint_intervals": [[a, b] for a, b in mask_intervals(relative_proxy, width=pwidth)],
            "physical_overlap_intervals": [[a, b] for a, b in mask_intervals(hit, width=256)],
        })
    return out
