<?php
// Minimal ASAN harness target.
session_start();
header('Content-Type: text/plain');
echo "ok sid=", session_id(), "\n";
