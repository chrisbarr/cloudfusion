--TEST--
AmazonCloudWatch::get_metric_statistics

--FILE--
<?php
	// Dependencies
	require_once dirname(__FILE__) . '/../../cloudfusion.class.php';

	// Get metrics
	$cw = new AmazonCloudWatch();
	$response = $cw->get_metric_statistics('CPUUtilization', 'Average', 'Percent', '1 August 2009', '2 August 2009');

	// Success?
	var_dump($response->isOK());
?>

--EXPECT--
bool(true)
