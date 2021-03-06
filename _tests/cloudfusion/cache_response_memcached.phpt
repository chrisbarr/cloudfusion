--TEST--
AmazonSDB::cache_response CacheMC

--SKIPIF--
<?php
	if (!method_exists('Memcache', 'connect')) print 'skip Memcached extension not available';
	elseif (!Memcache::connect('127.0.0.1')) print 'skip Memcached cannot connect to server';
?>

--FILE--
<?php
	// Dependencies
	require_once dirname(__FILE__) . '/../../cloudfusion.class.php';

	// Instantiate
	$sdb = new AmazonSDB();

	// First time pulls live data
	$response = $sdb->cache_response('list_domains', array(
		array('host' => '127.0.0.1')
	), 10);
	var_dump($response->isOK());

	// Second time pulls from cache
	$response = $sdb->cache_response('list_domains', array(
		array('host' => '127.0.0.1')
	), 10);
	var_dump($response->isOK());
?>

--EXPECT--
bool(true)
bool(true)
