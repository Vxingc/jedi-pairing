#!/usr/bin/env python3

from __future__ import annotations

import argparse
import html
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path


PAGE_WIDTH = 1600
PAGE_PADDING = 48
TITLE_GAP = 28
BLOCK_GAP = 22
TEXT_LINE_HEIGHT = 34
CODE_LINE_HEIGHT = 28
TEXT_MAX_WIDTH = 64
CODE_MAX_WIDTH = 96


@dataclass
class Block:
    kind: str
    lines: list[str]


@dataclass
class Section:
    index: int
    title: str
    blocks: list[Block]


def display_width(text: str) -> int:
    width = 0
    for ch in text:
        if ch == "\t":
            width += 4
            continue
        width += 2 if unicodedata.east_asian_width(ch) in {"W", "F"} else 1
    return width


def wrap_line(text: str, max_width: int) -> list[str]:
    if not text.strip():
        return [""]

    indent_match = re.match(r"^(\s*)", text)
    indent = indent_match.group(1) if indent_match else ""
    words = re.split(r"(\s+)", text.rstrip())

    wrapped: list[str] = []
    current = indent

    for piece in words:
        if piece == "":
            continue
        trial = current + piece
        if current.strip() == "":
            trial = current + piece.lstrip()

        if display_width(trial) <= max_width:
            current = trial
            continue

        if current.strip():
            wrapped.append(current.rstrip())
            current = indent + piece.lstrip()
            if display_width(current) <= max_width:
                continue

        chunk = ""
        for ch in piece.lstrip():
            trial_chunk = chunk + ch
            if display_width(indent + trial_chunk) > max_width and chunk:
                wrapped.append(indent + chunk)
                chunk = ch
            else:
                chunk = trial_chunk
        current = indent + chunk

    if current or not wrapped:
        wrapped.append(current.rstrip())
    return wrapped


def parse_markdown_sections(markdown_text: str) -> list[Section]:
    lines = markdown_text.splitlines()
    sections: list[Section] = []
    current_title = "Overview"
    current_blocks: list[Block] = []
    paragraph_buffer: list[str] = []
    in_code = False
    code_buffer: list[str] = []
    code_lang = ""
    section_index = 0

    def flush_paragraph() -> None:
        nonlocal paragraph_buffer
        if paragraph_buffer:
            current_blocks.append(Block(kind="text", lines=paragraph_buffer[:]))
            paragraph_buffer = []

    def flush_code() -> None:
        nonlocal code_buffer, code_lang
        current_blocks.append(Block(kind="code", lines=code_buffer[:]))
        code_buffer = []
        code_lang = ""

    def flush_section() -> None:
        nonlocal current_blocks, current_title, section_index
        flush_paragraph()
        if current_blocks:
            section_index += 1
            sections.append(Section(index=section_index, title=current_title, blocks=current_blocks[:]))
        current_blocks = []

    for line in lines:
        if line.startswith("```"):
            if in_code:
                flush_code()
                in_code = False
            else:
                flush_paragraph()
                in_code = True
                code_lang = line[3:].strip()
                code_buffer = []
            continue

        if in_code:
            code_buffer.append(line)
            continue

        if line.startswith("# "):
            continue

        if line.startswith("## "):
            flush_section()
            current_title = line[3:].strip()
            continue

        if line.strip() == "":
            flush_paragraph()
            continue

        paragraph_buffer.append(line)

    flush_paragraph()
    if in_code:
        flush_code()
    if current_blocks:
        section_index += 1
        sections.append(Section(index=section_index, title=current_title, blocks=current_blocks[:]))

    return sections


def slugify(text: str) -> str:
    text = text.lower()
    text = re.sub(r"`+", "", text)
    text = re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "-", text)
    text = re.sub(r"-{2,}", "-", text).strip("-")
    return text or "section"


def prepare_block_lines(block: Block) -> list[str]:
    prepared: list[str] = []
    max_width = CODE_MAX_WIDTH if block.kind == "code" else TEXT_MAX_WIDTH

    for raw_line in block.lines:
        line = raw_line.rstrip()
        if block.kind == "text" and line.lstrip().startswith("- "):
            bullet_prefix = line[: len(line) - len(line.lstrip())] + "• "
            content = line.lstrip()[2:]
            wrapped = wrap_line(content, max_width - display_width(bullet_prefix))
            for idx, part in enumerate(wrapped):
                if idx == 0:
                    prepared.append(bullet_prefix + part.lstrip())
                else:
                    prepared.append(" " * len(bullet_prefix) + part.lstrip())
            continue

        prepared.extend(wrap_line(line, max_width))

    return prepared


def render_section_svg(section: Section, input_name: str) -> str:
    y = PAGE_PADDING
    elements: list[str] = []

    elements.append(
        f'<rect x="0" y="0" width="{PAGE_WIDTH}" height="100%" fill="#f6f3ec" />'
    )
    elements.append(
        '<rect x="24" y="24" width="1552" height="calc(100% - 48px)" rx="28" fill="#fffdf8" stroke="#e6dccb" stroke-width="2" />'
    )

    elements.append(
        f'<text x="{PAGE_PADDING}" y="{y}" font-family="Noto Sans SC, PingFang SC, Microsoft YaHei, sans-serif" '
        'font-size="22" font-weight="700" fill="#8a6a2a">PSEUDOCODE SHEET</text>'
    )
    y += 44
    elements.append(
        f'<text x="{PAGE_PADDING}" y="{y}" font-family="Noto Sans SC, PingFang SC, Microsoft YaHei, sans-serif" '
        'font-size="44" font-weight="800" fill="#1d1b17">'
        f'{html.escape(section.title)}</text>'
    )
    y += 28
    elements.append(
        f'<text x="{PAGE_PADDING}" y="{y}" font-family="JetBrains Mono, SFMono-Regular, Consolas, monospace" '
        'font-size="18" fill="#7b7467">'
        f'{html.escape(input_name)}</text>'
    )
    y += TITLE_GAP

    for block in section.blocks:
        lines = prepare_block_lines(block)

        if block.kind == "code":
            box_x = PAGE_PADDING
            box_y = y
            box_width = PAGE_WIDTH - PAGE_PADDING * 2
            box_height = 34 + len(lines) * CODE_LINE_HEIGHT
            elements.append(
                f'<rect x="{box_x}" y="{box_y}" width="{box_width}" height="{box_height}" rx="20" fill="#171717" />'
            )
            elements.append(
                f'<text x="{box_x + 24}" y="{box_y + 28}" font-family="JetBrains Mono, SFMono-Regular, Consolas, monospace" '
                'font-size="16" font-weight="700" fill="#c4b48b">code</text>'
            )
            line_y = box_y + 62
            for line in lines:
                elements.append(
                    f'<text x="{box_x + 24}" y="{line_y}" xml:space="preserve" '
                    'font-family="JetBrains Mono, SFMono-Regular, Consolas, monospace" '
                    'font-size="22" fill="#f4f1ea">'
                    f'{html.escape(line)}</text>'
                )
                line_y += CODE_LINE_HEIGHT
            y = box_y + box_height + BLOCK_GAP
            continue

        line_y = y
        for line in lines:
            elements.append(
                f'<text x="{PAGE_PADDING}" y="{line_y}" xml:space="preserve" '
                'font-family="Noto Sans SC, PingFang SC, Microsoft YaHei, sans-serif" '
                'font-size="24" fill="#2f2a22">'
                f'{html.escape(line)}</text>'
            )
            line_y += TEXT_LINE_HEIGHT
        y = line_y + BLOCK_GAP

    total_height = int(y + PAGE_PADDING)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{PAGE_WIDTH}" height="{total_height}" '
        f'viewBox="0 0 {PAGE_WIDTH} {total_height}">'
        + "".join(elements)
        + "</svg>"
    )


def render_markdown_to_svgs(input_path: Path, output_dir: Path) -> list[Path]:
    sections = parse_markdown_sections(input_path.read_text(encoding="utf-8"))
    output_dir.mkdir(parents=True, exist_ok=True)

    output_paths: list[Path] = []
    for section in sections:
        slug = slugify(section.title)
        file_name = f"{section.index:02d}-{slug}.svg"
        output_path = output_dir / file_name
        svg = render_section_svg(section, input_path.name)
        output_path.write_text(svg, encoding="utf-8")
        output_paths.append(output_path)

    return output_paths


def main() -> None:
    parser = argparse.ArgumentParser(description="Render markdown pseudocode sections into SVG images.")
    parser.add_argument("input", type=Path, help="Path to the markdown pseudocode file.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory to place generated SVG files. Defaults to <input_stem>_svg.",
    )
    args = parser.parse_args()

    input_path = args.input.resolve()
    output_dir = args.output_dir or input_path.with_name(f"{input_path.stem}_svg")
    outputs = render_markdown_to_svgs(input_path, output_dir)

    print(f"Rendered {len(outputs)} SVG files to {output_dir}")
    for path in outputs:
        print(path)


if __name__ == "__main__":
    main()
