<?php
/**
 * Template preview — VULNERABLE BY DESIGN (lab only).
 *
 * The guard only blocks relative traversal and stream wrappers. Absolute
 * paths are still accepted, so an attacker can include any readable file,
 * including the PHP session file written by session.upload_progress.
 *
 * This is an application-level LFI, not CVE-2026-109618/109619.
 */
session_start();

$tpl = $_GET['tpl'] ?? 'pages/home.php';

// Naive guard: "no .. and no wrappers, therefore no LFI".
if (preg_match('~\.\.|php://|data://|phar://|zip://|expect://|file://|glob://|compress\.~i', $tpl)) {
    http_response_code(400);
    exit("blocked\n");
}

if ($tpl === '') {
    $tpl = 'pages/home.php';
}

include $tpl;
