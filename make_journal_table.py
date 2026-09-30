from PIL import Image, ImageDraw, ImageFont


OUT = "journal_llm_pipeline_table.jpg"


def font(path, size, index=0):
    return ImageFont.truetype(path, size=size, index=index)


SERIF = "/System/Library/Fonts/Supplemental/Times New Roman.ttf"
SERIF_BOLD = "/System/Library/Fonts/Supplemental/Times New Roman Bold.ttf"
SANS = "/System/Library/Fonts/Supplemental/Arial.ttf"
SANS_BOLD = "/System/Library/Fonts/Supplemental/Arial Bold.ttf"

W, H = 3000, 1060
img = Image.new("RGB", (W, H), "#ffffff")
draw = ImageDraw.Draw(img)

ink = "#1b1b1b"
muted = "#565656"
rule = "#c7ccd3"
heavy = "#32373d"
header_bg = "#edf2f7"
after_bg = "#f4fbf7"
before_bg = "#ffffff"
accent = "#2f6f5f"

title_font = font(SERIF_BOLD, 66)
subtitle_font = font(SERIF, 34)
header_font = font(SANS_BOLD, 36)
body_font = font(SANS, 43)
body_bold = font(SANS_BOLD, 43)
small_font = font(SERIF, 28)

title = "Comparison of Top-down Malicious Data Before and After Threat Model Pipeline"
subtitle = "Outcome threshold: ind1-4 < 50 and combined score >= 70"

draw.text((W // 2, 92), title, fill=ink, font=title_font, anchor="mm")
draw.text((W // 2, 154), subtitle, fill=muted, font=subtitle_font, anchor="mm")

left, right = 160, W - 160
top = 245
row_h = 116
header_h = 142
table_w = right - left
cols = [0.31, 0.23, 0.21, 0.13, 0.12]
x = [left]
for c in cols:
    x.append(x[-1] + int(table_w * c))
x[-1] = right

y0 = top
y1 = top + header_h
y2 = y1 + row_h
y3 = y2 + row_h
y4 = y3 + row_h
y5 = y4 + row_h

draw.rectangle((left, y0, right, y1), fill=header_bg)
draw.rectangle((left, y1, right, y2), fill=before_bg)
draw.rectangle((left, y2, right, y3), fill=before_bg)
draw.rectangle((left, y3, right, y4), fill=before_bg)
draw.rectangle((left, y4, right, y5), fill=after_bg)

draw.line((left, y0, right, y0), fill=heavy, width=4)
draw.line((left, y1, right, y1), fill=rule, width=2)
draw.line((left, y2, right, y2), fill=rule, width=2)
draw.line((left, y3, right, y3), fill=rule, width=2)
draw.line((left, y4, right, y4), fill=rule, width=2)
draw.line((left, y5, right, y5), fill=heavy, width=4)

for xx in x[1:-1]:
    draw.line((xx, y0, xx, y5), fill=rule, width=2)

draw.rectangle((left, y4, left + 10, y5), fill=accent)

headers = [
    "",
    "Favorable Cases",
    "Unfavorable\nCases",
    "Total\nScenarios",
    "Favorable\nData (%)",
]
rows = [
    ("Before LLM Pipeline", "21", "179", "200", "10.5%"),
    ("Blocked by Guardrails", "", "33", "200", ""),
    ("Safety Softening Phrases", "", "49", "200", ""),
    ("After LLM Pipeline", "118", "82", "200", "59.0%"),
]

for i, h in enumerate(headers):
    cx = (x[i] + x[i + 1]) // 2
    cy = y0 + header_h // 2
    if i == 1:
        draw.text((cx, cy - 19), h, fill=ink, font=header_font, anchor="mm")
        draw.text((cx, cy + 28), "(ind1-4 < 50; combined >= 70)", fill=muted, font=small_font, anchor="mm")
    elif "\n" in h:
        first, second = h.split("\n")
        draw.text((cx, cy - 22), first, fill=ink, font=header_font, anchor="mm")
        draw.text((cx, cy + 22), second, fill=ink, font=header_font, anchor="mm")
    else:
        draw.text((cx, cy), h, fill=ink, font=header_font, anchor="mm")

for r, row in enumerate(rows):
    y_center = y1 + row_h * r + row_h // 2
    label_font = body_bold if r == 3 else body_font
    value_font = body_font
    draw.text((x[0] + 32, y_center), row[0], fill=ink, font=label_font, anchor="lm")
    for i in range(1, len(row)):
        draw.text((x[i + 1] - 38, y_center), row[i], fill=ink, font=value_font, anchor="rm")

note = "Note. Values indicate scenarios meeting the favorable-data criterion before and after applying the LLM pipeline."
draw.text((left, y5 + 66), note, fill=muted, font=small_font, anchor="la")

# Thin outer border for journal reproduction.
draw.rectangle((left, y0, right, y5), outline=heavy, width=3)

img.save(OUT, quality=96, subsampling=0)
print(OUT)
