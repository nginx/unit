<?php

function quote($str) {
    return '"' . $str . '"';
}

header('Content-Type: application/json');

print "[" . join(",", array_map('quote', get_loaded_extensions())) . "]";

?>
