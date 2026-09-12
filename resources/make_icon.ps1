<#
 .SYNOPSIS
    Generates resources/usb-sentinel.ico from vector drawing code.

 .DESCRIPTION
    The .ico is committed to the repository (it is a build input for both
    the GUI executable's resource script and the NSIS installer), but it is
    generated rather than hand-drawn so it stays reproducible and
    reviewable: the artwork lives here as code, not as an opaque binary.

    Each size is rendered natively at its own resolution rather than
    downscaled from one large bitmap, so the 16x16 and 24x24 entries -- the
    ones Explorer, the taskbar and the title bar actually use most -- stay
    crisp instead of mushy.

    Encoding notes (this is the part that is easy to get subtly wrong):
      * Sizes below 256 are written as BMP/DIB payloads: a
        BITMAPINFOHEADER whose biHeight is DOUBLE the real height (the
        format reserves the second half for an AND mask), then 32bpp BGRA
        rows bottom-up, then the AND mask itself.
      * The AND mask is written all-zero. With a 32bpp entry Windows uses
        the alpha channel for transparency, but the mask must still be
        present and correctly sized or the entry is rejected/misparsed.
      * The 256x256 entry is written as a PNG payload, which is what every
        modern icon toolchain does (Vista+); writing it as a DIB would add
        ~260 KB for no benefit.
      * In ICONDIRENTRY, a 256-pixel dimension is encoded as the byte 0.

 .NOTES
    Run from anywhere:  powershell -ExecutionPolicy Bypass -File resources\make_icon.ps1
#>

[CmdletBinding()]
param(
    [string] $OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrEmpty($OutputPath)) {
    $here = Split-Path -Parent $MyInvocation.MyCommand.Path
    $OutputPath = Join-Path $here 'usb-sentinel.ico'
}

Add-Type -AssemblyName System.Drawing

# Design is authored against a 256x256 grid and scaled to each target size.
$DESIGN = 256.0

function New-IconBitmap {
    param([int] $Size)

    $bmp = New-Object System.Drawing.Bitmap($Size, $Size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    try {
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $g.Clear([System.Drawing.Color]::Transparent)

        $s = $Size / $DESIGN
        $g.ScaleTransform($s, $s)

        # --- Shield silhouette -------------------------------------------------
        # Classic heater shield: flat top, straight shoulders, curving to a
        # point at the bottom. Kept deliberately wide so it still reads as a
        # shield (rather than a blob) once it is 16 pixels tall.
        $shield = New-Object System.Drawing.Drawing2D.GraphicsPath
        $shield.AddLine(128.0, 18.0, 228.0, 54.0)
        $shield.AddLine(228.0, 54.0, 228.0, 122.0)
        $shield.AddBezier(228.0, 122.0, 228.0, 188.0, 182.0, 226.0, 128.0, 242.0)
        $shield.AddBezier(128.0, 242.0, 74.0, 226.0, 28.0, 188.0, 28.0, 122.0)
        $shield.AddLine(28.0, 122.0, 28.0, 54.0)
        $shield.CloseFigure()

        $gradRect = New-Object System.Drawing.RectangleF(28.0, 18.0, 200.0, 224.0)
        $fill = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
            $gradRect,
            [System.Drawing.Color]::FromArgb(255, 74, 158, 245),
            [System.Drawing.Color]::FromArgb(255, 21, 82, 176),
            [System.Drawing.Drawing2D.LinearGradientMode]::Vertical)
        $g.FillPath($fill, $shield)
        $fill.Dispose()

        # Border: darker than the gradient's darkest stop so the silhouette
        # keeps a hard edge against a light taskbar or a white title bar.
        $borderWidth = [Math]::Max(2.0, 9.0)
        $border = New-Object System.Drawing.Pen(
            [System.Drawing.Color]::FromArgb(255, 12, 58, 124), $borderWidth)
        $border.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
        $g.DrawPath($border, $shield)
        $border.Dispose()
        $shield.Dispose()

        # --- Checkmark ---------------------------------------------------------
        # Stroke weight is expressed in design units, but floored in DEVICE
        # pixels: at 16x16 a proportional stroke works out to ~1.4px, which
        # antialiases into an illegible grey smear. Two device pixels is the
        # minimum that still reads as a checkmark.
        $strokeDesign = 26.0
        $strokeDevice = $strokeDesign * $s
        if ($strokeDevice -lt 2.0) { $strokeDesign = 2.0 / $s }

        $check = New-Object System.Drawing.Drawing2D.GraphicsPath
        $check.AddLine(74.0, 130.0, 112.0, 170.0)
        $check.AddLine(112.0, 170.0, 186.0, 88.0)

        $checkPen = New-Object System.Drawing.Pen(
            [System.Drawing.Color]::FromArgb(255, 255, 255, 255), $strokeDesign)
        $checkPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
        $checkPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
        $checkPen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
        $g.DrawPath($checkPen, $check)
        $checkPen.Dispose()
        $check.Dispose()
    }
    finally {
        $g.Dispose()
    }
    return $bmp
}

function ConvertTo-DibPayload {
    param([System.Drawing.Bitmap] $Bitmap)

    $w = $Bitmap.Width
    $h = $Bitmap.Height

    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($ms)
    try {
        # BITMAPINFOHEADER. biHeight is doubled: colour rows + AND mask rows.
        $bw.Write([uint32] 40)      # biSize
        $bw.Write([int32] $w)       # biWidth
        $bw.Write([int32] ($h * 2)) # biHeight (colour + mask)
        $bw.Write([uint16] 1)       # biPlanes
        $bw.Write([uint16] 32)      # biBitCount
        $bw.Write([uint32] 0)       # biCompression = BI_RGB
        $bw.Write([uint32] 0)       # biSizeImage (may be 0 for BI_RGB)
        $bw.Write([int32] 0)        # biXPelsPerMeter
        $bw.Write([int32] 0)        # biYPelsPerMeter
        $bw.Write([uint32] 0)       # biClrUsed
        $bw.Write([uint32] 0)       # biClrImportant

        # Colour rows, bottom-up, BGRA. LockBits gives top-down rows for
        # Format32bppArgb, so they are emitted in reverse.
        $rect = New-Object System.Drawing.Rectangle(0, 0, $w, $h)
        $data = $Bitmap.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly,
                                 [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        try {
            $stride = $data.Stride
            $row = New-Object byte[] $stride
            for ($y = $h - 1; $y -ge 0; $y--) {
                $src = [IntPtr]::Add($data.Scan0, $y * $stride)
                [System.Runtime.InteropServices.Marshal]::Copy($src, $row, 0, $stride)
                $bw.Write($row, 0, $w * 4)
            }
        }
        finally {
            $Bitmap.UnlockBits($data)
        }

        # AND mask: all zero (fully opaque). Each row padded to 4 bytes.
        $maskStride = [int](([Math]::Floor(($w + 31) / 32)) * 4)
        $maskRow = New-Object byte[] $maskStride
        for ($y = 0; $y -lt $h; $y++) {
            $bw.Write($maskRow, 0, $maskStride)
        }

        $bw.Flush()
        return $ms.ToArray()
    }
    finally {
        $bw.Dispose()
        $ms.Dispose()
    }
}

function ConvertTo-PngPayload {
    param([System.Drawing.Bitmap] $Bitmap)

    $ms = New-Object System.IO.MemoryStream
    try {
        $Bitmap.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        return $ms.ToArray()
    }
    finally {
        $ms.Dispose()
    }
}

$sizes = @(16, 24, 32, 48, 64, 128, 256)
$entries = @()

foreach ($size in $sizes) {
    $bmp = New-IconBitmap -Size $size
    try {
        if ($size -ge 256) {
            $payload = ConvertTo-PngPayload -Bitmap $bmp
        }
        else {
            $payload = ConvertTo-DibPayload -Bitmap $bmp
        }
        $entries += [pscustomobject]@{ Size = $size; Payload = $payload }
    }
    finally {
        $bmp.Dispose()
    }
}

$out = New-Object System.IO.MemoryStream
$w = New-Object System.IO.BinaryWriter($out)
try {
    # ICONDIR
    $w.Write([uint16] 0)                 # reserved
    $w.Write([uint16] 1)                 # type: 1 = icon
    $w.Write([uint16] $entries.Count)

    # ICONDIRENTRY is 16 bytes each; payloads follow the whole directory.
    $offset = 6 + (16 * $entries.Count)
    foreach ($e in $entries) {
        $dim = if ($e.Size -ge 256) { 0 } else { $e.Size }
        $w.Write([byte] $dim)            # width  (0 means 256)
        $w.Write([byte] $dim)            # height (0 means 256)
        $w.Write([byte] 0)               # colour count (0 for >8bpp)
        $w.Write([byte] 0)               # reserved
        $w.Write([uint16] 1)             # colour planes
        $w.Write([uint16] 32)            # bits per pixel
        $w.Write([uint32] $e.Payload.Length)
        $w.Write([uint32] $offset)
        $offset += $e.Payload.Length
    }
    foreach ($e in $entries) {
        $w.Write($e.Payload, 0, $e.Payload.Length)
    }
    $w.Flush()

    [System.IO.File]::WriteAllBytes($OutputPath, $out.ToArray())
}
finally {
    $w.Dispose()
    $out.Dispose()
}

$info = Get-Item $OutputPath
Write-Host ("Wrote {0} ({1} bytes, {2} entries: {3})" -f `
    $info.FullName, $info.Length, $entries.Count, ($sizes -join ', '))
