<?php
/**
 * PixelVault — CTF target (intentionally vulnerable, lab only).
 *
 * The vulnerability is an APPLICATION bug: view.php includes a
 * user-controlled path. It is not CVE-2026-109618/109619.
 */
session_start();
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PixelVault</title>
  <style>
    body{font-family:ui-monospace,Menlo,monospace;background:#0d1117;color:#c9d1d9;max-width:720px;margin:60px auto;padding:0 20px}
    h1{color:#58a6ff;font-size:22px}
    .card{border:1px solid #30363d;border-radius:8px;padding:20px;margin:18px 0;background:#161b22}
    input[type=file]{color:#c9d1d9}
    button{background:#238636;color:#fff;border:0;padding:8px 14px;border-radius:6px;cursor:pointer}
    code{background:#0d1117;padding:2px 5px;border-radius:4px;color:#7ee787}
    a{color:#58a6ff}
  </style>
</head>
<body>
  <h1>PixelVault</h1>
  <p>Upload an image, then preview it as a template.</p>

  <div class="card">
    <form action="index.php" method="post" enctype="multipart/form-data">
      <p><input type="file" name="image"></p>
      <p><button type="submit">Upload</button></p>
    </form>
    <?php if (!empty($_FILES)): ?>
      <p>Received <?= count($_FILES) ?> file(s). Preview:
        <a href="view.php?tpl=pages/result.php">rendered output</a></p>
    <?php endif; ?>
  </div>

  <div class="card">
    <p><strong>Template preview</strong></p>
    <p><a href="view.php?tpl=pages/home.php">home</a> ·
       <a href="view.php?tpl=pages/about.php">about</a></p>
    <p style="color:#8b949e;font-size:12px">session id: <code><?= htmlspecialchars(session_id()) ?></code></p>
  </div>
</body>
</html>
