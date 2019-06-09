---
title: HXP 2017 pdf.pdf
authors: Lense
date: 2017-11-19
categories: forensics
---

>RTFM! and a link to [pdf.pdf]({{ site.baseurl }}/assets/pdf.pdf).

The PDF contained a bunch of different types of content, like text, a vector
drawing, a bitmap image, embedded fonts, internal and external links, annotated
rectangles around the links, table of contents metadata, and presumably the
flag. It ended with a link to the
[PDF spec](http://www.adobe.com/content/dam/acom/en/devnet/pdf/pdfs/PDF32000_2008.pdf),
and we took that to mean that we should write a PDF parser.

### PDF file format overview

It turns out that while rendering PDFs is extremely painful, just parsing a PDF
is only moderately painful, and the spec isn't as bad as I was expecting.

#### File sections

##### Header
The first line is a comment (starting with `%`) with the PDF version number.
The challenge used version 1.5.
The second line is a comment with 4 non-ascii bytes, designed to keep text
viewers from trying to render PDFs as plaintext.

##### Body

The body is a series of objects. They aren't rendered implicitly, but they can
be referenced by other objects and the XRef table at the end.

##### Footer

The footer can have a whole bunch of different types that render the PDF
differently, but since we were just trying to parse the PDF, we didn't deal
with it much. At a high level, the footer contains a cross-reference table that
points to byte-offsets in the file of objects.

#### Object types

In this PDF, the body consisted entirely of indirect objects. Those indirect
objects contained streams of compressed data, which contained one or more
direct objects of arbitrary type. I'm sure there are many other ways that PDFs
can be structured, but we just had to deal with this.

##### Indirect objects

Format:

```
<object number> <generation number> obj
<contents (stream)>
endobj
```

In our PDF, generation number was always 0 and the contents were always
streams. To point to the stream, other objects can use a reference:
`<object number> <generation number> R`.

##### Dictionaries

Format: `<< Key Value Key Value ... >>`

Most of the objects in the PDF were dictionaries. Among other things, these are
used for content hierarchies, like defining what pages there were and what
contents were on each page.

##### Streams

Format:

```
<dictionary>
stream
<data>
endstream
```

Streams consist of a dictionary of metadata and stream data. The streams in
this PDF set `/Filter` to `/FlateDecode` in their dictionaries, which meant
that the streams were compressed with zlib-flate. Some streams also had more
complicated compression methods that we looked at and decided didn't contain
the flag.

##### Hex strings

Format: `<hex...>`

In this PDF, they were all UTF-16.

##### Other objects

PDFs also have ints, floats, arrays, strings, and more, but they're more
self-explanatory and not as important for the challenge.

#### But where's the flag?

We wrote a parser for almost all the objects of the binary, but it didn't
render anything, and so we didn't see the flag just lying there. After spinning
our wheels for a while, we had the idea to look for something hidden. We made a
list of all the references and looked for an object that was never referenced.

Object 30 was never referenced:

```
<< /Contents [ 83 0 R ] /Parent 58 0 R /Resources 43 0 R /Type /Page >>
```

It was a hidden page with page contents of object 83 and resource object 43.
Object 43 was a reference to XObject 85, a vector image. Hawkheart wrote a
renderer for it, and we got this nice picture of a flag:

![vector image of a flag]({{ site.baseurl }}/assets/hxp_pdf_vector_flag.png)

That's pretty, but not very useful. Object 83 was trickier:

```
q 1 0 0 1 72 769.89 cm q .5489 0 0 .5489 70.2 -62.656 cm q 1 0 0 1 155.62 -138.895 cm /Fm1 Do Q Q BT /F3 11.9552 Tf -1.134 -335.582 Td[<0075>81<0032001c003f0035>-433<0075>81<0051006d>-325<004b001c002f0032>-326<00420069>-326<001c004d002f>-326<00370051006d004d002f>-326<0069003f0032>-326<004b001c003b0042002b>-326<007e001c003b002c>]TJ ET BT /F6 17.2154 Tf -1.134 -371.697 Td[<004e005a0044005e004500580057004e001d00540048>17<005b005d0054004b005b005d004c004d00540055004e>31<0058005400510049004a004a0049002c00460054004400570046001600540049002c0054005b005d004700540056005b005b005300540044004d004b0060>]TJ ET q .5489 0 0 .5489 70.2 -315.33 cm q 1 0 0 1 155.62 -699.024 cm /Fm1 Do Q Q BT /F3 11.9552 Tf 222.709 -728.912 Td[<0039>]TJ ET Q
```

It's a graphics object (or something, not exactly sure) containing operators
and operands in postfix order.
[Table 51](https://www.adobe.com/content/dam/acom/en/devnet/pdf/pdfs/PDF32000_2008.pdf#G7.3952560)
of the spec was very useful for figuring out what everything was.

Going through it:

- `q` does something about graphics state. ignored
- `# # # # # # cm` also does something about graphics state. ignored
- `<name> Do` renders the name object. This is the flag image
- `Q` does the opposite of `q`. ignored
- `BT` begins a text object. This is what we're interested in
- `<font name> <font size> Tf` sets the current font. We ignored this at first,
  but it turned out to be very important
- `# # Td` sets the text position. ignored
- `<text array> TJ` renders the hex strings in the array as text, adjusting the
  position of the chatacter by the numbers. We extracted the hex strings and
  ignored the positioning data

So we have 3 hex strings, but these don't translate to ascii. After some time,
we looked into how the fonts render. The first hex string uses font F3:

```
<< /BaseFont /MXUXTP+LMSans12-Regular-Identity-H /DescendantFonts [ 14 0 R ] /Encoding /Identity-H /Subtype /Type0 /ToUnicode 76 0 R /Type /Font >>
```

The Encoding Identity-H means that the encoding is 1-1, so we don't need to
worry about that. The ToUnicode reference, however is something we need to
worry about. Object 76 is some kind of font PDF metadata thing containing

```
71 beginbfchar
<001B> <0041>
<001C> <0061>
<0022> <0042>
<0023> <0062>
<0026> <007B>
<0027> <007D>
<002A> <0043>
...
```

When we mapped the characters in the hex string from the left column to the
right column for both of te fonts, we got:

```
Yeah!Youmadeitandfoundthemagicflag:kwa{butk:qexzqhxzijqrkuqnfggfIcqatc3qfIqxzdqsxxpqajh}
```

Well... That's something... The readable part was in font F3 and the unreadable
part was in font F6. After a couple hours staring at this and trying other
character replacements, we noticed a line in the metadata for font F6:

```
/CMapName /.-DejaVuSansCondensedmod.ttf,000-UTF16 def
```

All the other fonts had lines that looked like:

```
/CMapName /-usr-share-texlive-texmf-dist-fonts-opentype-public-lm-lmsans10-bold.otf,000-UTF16 def
```

The relative path and having it called "mod" seemed suspicious, so we extracted
the ttf file (object 99) and opened it in FontForge.

![glyphs that look like a rearranged flag]({{ site.baseurl }}/assets/hxp_pdf_fontforge.png)

That doesn't look like the alphabet. Since this was 6am, we decoded the flag by
hand, getting

```
hxp{Yeah!_y0u_f0und_The_missing_pag3_in_0ur_c00l_pdf}
```

## Code

### PDF parser

This code will parse the top-level objects and dump streams to files. It did a
lot more parsing and formatting, but none of that was relevant to the
challenge.

``` python
#!/usr/bin/python3
"""
PDF top-level parser

Don't expect this to work on anything except pdf.pdf
"""

import binascii
import zlib


WHITESPACE = [0, 0x9, 0xa, 0xc, 0xd, 0x20]


def count_whitespace(pdf):
    for pointer in range(len(pdf)):
        if pdf[pointer] not in WHITESPACE:
            return pointer


def parse_line(pdf):
    line_len = pdf.index(b'\n')
    return line_len+1, pdf[:line_len]


def parse_int(pdf):
    for pointer in range(len(pdf)):
        if pdf[pointer] in WHITESPACE:
            return pointer+1, int(pdf[:pointer])


def parse_float(pdf):
    for pointer in range(len(pdf)):
        if pdf[pointer] in WHITESPACE:
            return pointer+1, float(pdf[:pointer])


def parse_hex(pdf):
    if pdf[0:1] != b'<':
        raise ValueError('invalid hex')
    line_len = pdf.index(b'>')
    hex_data = binascii.unhexlify(pdf[1:line_len])
    return line_len+1, hex_data


def parse_name(pdf):
    if pdf[0:1] != b'/':
        raise ValueError('invalid name')
    for pointer in range(len(pdf)):
        if pdf[pointer] in WHITESPACE:
            return pointer+1, pdf[1:pointer]


def parse_obj(pdf):
    print(f'Parsing "{pdf[:16]}..."')
    # Comment
    if pdf[0:1] == b'%':
        comment_len, comment = parse_line(pdf)
        return comment_len, {'type': 'comment', 'contents': comment}

    # Name
    if pdf[0:1] == b'/':
        return parse_name(pdf)

    # startxref <<< not standard
    if pdf[1:10] == b'startxref':
        # TODO optional Trailer
        startxref_len, startxref = parse_int(pdf[11:])
        return 11 + startxref_len + 6, \
            {'type': 'startxref', 'contents': startxref}

    # Array
    if pdf[0:1] == b'[':
        pointer = 1 + count_whitespace(pdf[1:])
        d = list()
        while pdf[pointer:pointer+1] != b']':
            obj_len, obj = parse_obj(pdf[pointer:])
            d.append(obj)
            pointer += obj_len
        return pointer+2, {'type': 'array', 'contents': d}

    # Dictionary
    if pdf[0:2] == b'<<':
        pointer = 3
        d = dict()
        while pdf[pointer:pointer+2] != b'>>':
            key_len, key = parse_name(pdf[pointer:])
            value_len, value = parse_obj(pdf[pointer+key_len:])
            d[key] = value
            pointer += key_len + value_len
        pointer += 3
        if pdf[pointer:pointer+6] == b'stream':
            stream = pdf[pointer+7:pointer+7+d[b'Length']]
            pointer += 7 + d[b'Length'] + 10
            d['*stream'] = stream
        return pointer, {'type': 'dictionary', 'contents': d}

    # Reference
    try:
        len1, object_number = parse_int(pdf)
        len2, generation_number = parse_int(pdf[len1:])
        if pdf[len1+len2:len1+len2+1] != b'R':
            raise ValueError
        return len1+len2+2, \
            {
                'type': 'reference',
                'contents': None,
                'object_number': object_number,
                'generation_number': generation_number
            }
    except ValueError:
        pass

    # Indirect object
    try:
        len1, object_number = parse_int(pdf)
        len2, generation_number = parse_int(pdf[len1:])
        if pdf[len1+len2:len1+len2+3] != b'obj':
            raise ValueError
        inner_len, inner_obj = parse_obj(pdf[len1+len2+4:])
        return len1+len2+3+inner_len+8, \
            {
                'type': 'indirect object',
                'contents': inner_obj,
                'object_number': object_number,
                'generation_number': generation_number
            }
    except ValueError:
        pass

    # Hex string
    if pdf[0:1] == b'<':
        return parse_hex(pdf)

    # Integer
    try:
        return parse_int(pdf)
    except ValueError:
        pass

    # Float
    try:
        return parse_float(pdf)
    except ValueError:
        pass

    print('!!!Failed to parse!!!')
    raise Exception


def parse_pdf(pdf):
    # Parse PDF and extract objects into data
    data = []
    pointer = 0
    while pointer < len(pdf):
        try:
            obj_len, obj = parse_obj(pdf[pointer:])
        except Exception:
            print(f'Failed at {pointer}, "{pdf[pointer:pointer+16]}..."')
            raise
        pointer += obj_len
        data.append(obj)
    return data


def dump_objects(data):
    # Go through and dump parsed objects
    for obj in data:
        # We don't care if it's not an indirect object
        if obj['type'] != 'indirect object':
            print('not dumping:', obj)
            continue

        # Assume indirect objects are streams
        print('dumping indirect object:', obj['object_number'])
        assert obj['contents']['type'] == 'dictionary'
        assert '*stream' in obj['contents']['contents']
        obj_dict = obj['contents']['contents']
        stream = obj_dict['*stream']

        # De-Flate
        if b'Filter' in obj_dict and b'FlateDecode' in obj_dict[b'Filter']:
            stream = zlib.decompress(stream)

        # Dump to file
        with open(
                f'{obj["object_number"]}_{obj["generation_number"]}.bin',
                'wb') as f:
            f.write(stream)


if __name__ == '__main__':
    with open('pdf.pdf', 'rb') as f:
        pdf = f.read()
    data = parse_pdf(pdf)
    dump_objects(data)
```

### Vector image painter

Hawkheart wrote this to render line drawings from object 85. It shows a nice
flag, but not the flag we wanted :(

```python
import matplotlib.path as mpath
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt

def cmykToRgb(c, m, y, k) :
    # Thanks to Stack Overflow for this function :)
    r = round(255.0 - ((min(1.0, c * (1.0 - k) + k)) * 255.0))
    g = round(255.0 - ((min(1.0, m * (1.0 - k) + k)) * 255.0))
    b = round(255.0 - ((min(1.0, y * (1.0 - k) + k)) * 255.0))
    return (r,g,b)

Path = mpath.Path

with open("85_0.bin") as f:
    s = f.read()

fig, ax = plt.subplots()


current_path = []
current_path_actions = []
current_color = (0, 0, 0)
linewidth = 1

for line in s.split('\n'):
    line = line.strip()
    line = line.rstrip()
    if not line:
        continue
    if line[-2:] == ' m':
        current_path_actions.append(Path.MOVETO)
        x,y,m = line.split()
        current_path.append((float(x), float(y)))
    elif line[-1] == "w":
        width, _ = line.split()
        linewidth = float(width)/2
    elif line[-2:] == 're':
        x, y, width, height, _ = line.split()
        x = float(x)
        y = float(y)
        width = float(width)
        height = float(height)
        current_path.extend([(x,y), (x+width,y),(x+width,y+height), (x, y+height), (x, y)])
        current_path_actions.extend([Path.MOVETO,Path.LINETO,Path.LINETO,Path.LINETO,Path.LINETO])
    elif line[-1] == 'k':
        c,m,y,k,_ = line.split()
        c = float(c)
        m = float(m)
        y = float(y)
        k = float(k)
        r,g,b =  cmykToRgb(c,m,y,k)
        current_color = (r/255.0, g/255.0, b/255.0)
    elif line[-1] == 'c':
        x1, y1, x2, y2, x3, y3, c = line.split()
        x1 = float(x1)
        x2 = float(x2)
        x3 = float(x3)
        y1 = float(y1)
        y2 = float(y2)
        y3 = float(y3)
        current_path.append((x1, y1))
        current_path.append((x2, y2))
        current_path.append((x3, y3))
        current_path_actions.extend([Path.CURVE4]*3)
    elif line[-1] == "l":
        x, y, l = line.split()
        x = float(x)
        y = float(y)
        current_path.append((x,y))
        current_path_actions.append(Path.LINETO)
    if line[0] in ["W", "S"]:
        current_path.append(current_path[0])
        current_path_actions.append(Path.CLOSEPOLY)
        patch = mpatches.PathPatch(Path(current_path, current_path_actions), transform=ax.transData, linewidth=linewidth)
        ax.add_patch(patch)
        current_path = []
        current_path_actions = []
    elif line[0] == 'f':
        current_path.append(current_path[0])
        current_path_actions.append(Path.CLOSEPOLY)
        patch = mpatches.PathPatch(Path(current_path, current_path_actions), fc=current_color,transform=ax.transData, fill=True,linewidth=0)
        ax.add_patch(patch)
        current_path = []
        current_path_actions = []

ax.plot()
plt.show()
```
