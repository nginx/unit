<?php
date_default_timezone_set('Europe/Moscow');
$d = new DateTime('2011-01-01T15:03:01.012345');
echo $d->format('u');
?>
