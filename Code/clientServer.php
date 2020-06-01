<?php
error_reporting(E_ERROR | E_PARSE);
header("Access-Control-Allow-Origin: *");
$site=$_POST['url'];
$html = file_get_contents($site);

$bytes=file_put_contents('markup.txt', $html);

$decision=exec("C:/Users/Ruby/AppData/Local/Programs/Python/Python37/python result4chrome.py $site 2>&1 ");
echo $decision;
?>