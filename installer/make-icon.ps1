# Draws the app icon (a shield with a check mark) and writes assets/icon.ico (PNG-compressed, 256/48/32/16 px).
# Pure Windows, no tools: System.Drawing is part of .NET on every Windows install.
param([string]$Out = (Join-Path $PSScriptRoot '..\assets\icon.ico'))
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

function Draw-Shield([int]$size) {
  $bmp = New-Object System.Drawing.Bitmap $size, $size
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.SmoothingMode = 'AntiAlias'
  $g.Clear([System.Drawing.Color]::Transparent)
  $s = $size / 256.0
  # shield outline
  $path = New-Object System.Drawing.Drawing2D.GraphicsPath
  $pts = @(
    (New-Object System.Drawing.PointF (128 * $s), (14 * $s)),
    (New-Object System.Drawing.PointF (226 * $s), (52 * $s)),
    (New-Object System.Drawing.PointF (218 * $s), (142 * $s)),
    (New-Object System.Drawing.PointF (128 * $s), (244 * $s)),
    (New-Object System.Drawing.PointF (38 * $s), (142 * $s)),
    (New-Object System.Drawing.PointF (30 * $s), (52 * $s))
  )
  $path.AddPolygon($pts)
  $fill = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 26, 86, 219))
  $g.FillPath($fill, $path)
  # check mark
  $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::White), ([single](26 * $s))
  $pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
  $g.DrawLines($pen, [System.Drawing.PointF[]]@(
    (New-Object System.Drawing.PointF (78 * $s), (132 * $s)),
    (New-Object System.Drawing.PointF (114 * $s), (168 * $s)),
    (New-Object System.Drawing.PointF (180 * $s), (92 * $s))
  ))
  $g.Dispose()
  return $bmp
}

$sizes = @(256, 48, 32, 16)
$pngs = foreach ($sz in $sizes) {
  $bmp = Draw-Shield $sz
  $ms = New-Object System.IO.MemoryStream
  $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
  $bmp.Dispose()
  ,@{ size = $sz; bytes = $ms.ToArray() }
}

# ICO container: 6-byte header, 16-byte entry per image, then the PNG blobs.
$dir = Split-Path -Parent $Out
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$fs = [System.IO.File]::Create($Out)
$bw = New-Object System.IO.BinaryWriter $fs
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$pngs.Count)
$offset = 6 + 16 * $pngs.Count
foreach ($p in $pngs) {
  $dim = if ($p.size -ge 256) { 0 } else { $p.size }
  $bw.Write([byte]$dim); $bw.Write([byte]$dim); $bw.Write([byte]0); $bw.Write([byte]0)
  $bw.Write([uint16]1); $bw.Write([uint16]32)
  $bw.Write([uint32]$p.bytes.Length); $bw.Write([uint32]$offset)
  $offset += $p.bytes.Length
}
foreach ($p in $pngs) { $bw.Write($p.bytes) }
$bw.Dispose(); $fs.Dispose()
Write-Host "icon written: $Out ($((Get-Item $Out).Length) bytes)"
