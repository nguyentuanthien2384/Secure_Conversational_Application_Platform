from pathlib import Path

from PIL import Image, ImageDraw, ImageOps


root = Path(r"D:\btl\scap\tmp\pdfs")
pages = sorted(root.glob("security_report_page-*.png"))

for group_index, start in enumerate(range(0, len(pages), 9), 1):
    sheet = Image.new("RGB", (3 * 440, 3 * 630), "#dddddd")
    draw = ImageDraw.Draw(sheet)
    for index, page in enumerate(pages[start : start + 9]):
        with Image.open(page) as source:
            image = source.convert("RGB")
            image.thumbnail((420, 594))
            image = ImageOps.expand(image, border=2, fill="#777777")
        x = (index % 3) * 440 + 10
        y = (index // 3) * 630 + 24
        sheet.paste(image, (x, y))
        draw.text((x, y - 18), page.stem[-2:], fill="black")
    sheet.save(root / f"security_report_contact_{group_index}.jpg", quality=90)
