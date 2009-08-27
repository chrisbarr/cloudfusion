<?php
/**
 * File: Amazon SQS Queue
 * 	Queue-centric wrapper for Amazon Simple Queue Service
 *
 * Version:
 * 	2009.08.26
 *
 * Copyright:
 * 	2006-2009 Foleeo, Inc., and contributors.
 *
 * License:
 * 	Simplified BSD License - http://opensource.org/licenses/bsd-license.php
 *
 * See Also:
 * 	CloudFusion - http://getcloudfusion.com
 * 	Amazon SQS - http://aws.amazon.com/sqs
 */


/*%******************************************************************************************%*/
// CONSTANTS

/**
 * Constant: SQSQUEUE_DEFAULT_ERROR
 * 	Specify the default error message.
 */
define('SQSQUEUE_DEFAULT_ERROR', 'The required queue URL was not provided in a previous action and we have NO idea which queue to execute this action on.');


/*%******************************************************************************************%*/
// EXCEPTIONS

/**
 * Exception: SQSQueue_Exception
 * 	Default SQS SQSQueue_Exception.
 */
class SQSQueue_Exception extends Exception {}


/*%******************************************************************************************%*/
// MAIN CLASS

/**
 * Class: AmazonSQSQueue
 * 	Container for all Amazon SQS-related methods. Inherits additional methods from AmazonSQS.
 *
 * Extends:
 * 	AmazonSQS
 */
class AmazonSQSQueue extends AmazonSQS
{
	/**
	 * Property: queue_url
	 * 	The queue URL to use for every request.
	 */
	var $queue_url;

	/*%******************************************************************************************%*/
	// CONSTRUCTOR

	/**
	 * Method: __construct()
	 * 	The constructor
	 *
	 * Access:
	 * 	public
	 *
	 * Parameters:
	 * 	queue - _string_ (Optional) The NAME for the queue to revolve around. Set as null if you plan to create a new queue, as it will be auto-set.
	 * 	key - _string_ (Optional) Your Amazon API Key. If blank, it will look for the <AWS_KEY> constant.
	 * 	secret_key - _string_ (Optional) Your Amazon API Secret Key. If blank, it will look for the <AWS_SECRET_KEY> constant.
	 *
	 * Returns:
	 * 	_boolean_ false if no valid values are set, otherwise true.
 	 *
	 * See Also:
	 * 	Example Usage - http://getcloudfusion.com/docs/examples/sqsqueue/__construct.phps
	 */
	public function __construct($queue = null, $key = null, $secret_key = null)
	{
		$this->queue_url = SQS_DEFAULT_URL . '/' . $queue;
		return parent::__construct($key, $secret_key);
	}


	/*%******************************************************************************************%*/
	// QUEUES

	/**
	 * Method: create_queue()
	 * 	Identical to <AmazonSQS::create_queue()>. The queue URL created from this method will replace the queue URL already being used with this class.
	 *
	 * 	New queue URL will NOT automatically apply when using MultiCurl for parallel requests.
	 *
	 * Access:
	 * 	public
	 *
	 * Parameters:
	 * 	queue_name - See <AmazonSQS::create_queue()>.
	 * 	returnCurlHandle - See <AmazonSQS::create_queue()>.
	 *
	 * Returns:
	 * 	<ResponseCore> object
 	 *
	 * See Also:
	 * 	Example Usage - http://getcloudfusion.com/docs/examples/sqsqueue/create_queue.phps
	 */
	public function create_queue($queue_name, $returnCurlHandle = null)
	{
		$data = parent::create_queue($queue_name, $returnCurlHandle);

		if ($data instanceof ResponseCore)
		{
			$this->queue_url = (string) $data->body->CreateQueueResult->QueueUrl;
		}

		return $data;
	}

	/**
	 * Method: delete_queue()
	 * 	Identical to <AmazonSQS::delete_queue()>, except that you don't need to pass in a queue URL.
	 *
	 * Access:
	 * 	public
	 *
	 * Parameters:
	 * 	returnCurlHandle - See <AmazonSQS::delete_queue()>.
	 *
	 * Returns:
	 * 	<ResponseCore> object
 	 *
	 * See Also:
	 * 	Example Usage - http://getcloudfusion.com/docs/examples/sqsqueue/delete_queue.phps
	 */
	public function delete_queue($returnCurlHandle = null)
	{
		if ($this->queue_url)
		{
			return parent::delete_queue($this->queue_url, $returnCurlHandle);
		}

		throw new SQSQueue_Exception(SQSQUEUE_DEFAULT_ERROR);
	}

	/**
	 * Method: get_queue_attributes()
	 * 	Identical to <AmazonSQS::get_queue_attributes()>, except that you don't need to pass in a queue URL.
	 *
	 * Access:
	 * 	public
	 *
	 * Parameters:
 	 * 	attributes - _string_|_array_ (Optional) The attribute you want to get. Setting this value to 'All' returns all the queue's attributes. Pass a string for a single attribute, or an indexed array for multiple attributes. Possible values are 'All', 'ApproximateNumberOfMessages', 'VisibilityTimeout', 'CreatedTimestamp', 'LastModifiedTimestamp', and 'Policy'. Defaults to 'All'.
	 * 	returnCurlHandle - See <AmazonSQS::get_queue_attributes()>.
	 *
	 * Returns:
	 * 	<ResponseCore> object
 	 *
	 * See Also:
	 * 	Example Usage - http://getcloudfusion.com/docs/examples/sqsqueue/get_queue_attributes.phps
	 */
	public function get_queue_attributes($attributes = 'All', $returnCurlHandle = null)
	{
		if ($this->queue_url)
		{
			return parent::get_queue_attributes($this->queue_url, $attributes, $returnCurlHandle);
		}

		throw new SQSQueue_Exception(SQSQUEUE_DEFAULT_ERROR);
	}

	/**
	 * Method: set_queue_attributes()
	 * 	Identical to <AmazonSQS::set_queue_attributes()>, except that you don't need to pass in a queue URL.
	 *
	 * Access:
	 * 	public
	 *
	 * Parameters:
	 * 	opt - See <AmazonSQS::set_queue_attributes()>.
	 *
	 * Returns:
	 * 	<ResponseCore> object
 	 *
	 * See Also:
	 * 	Example Usage - http://getcloudfusion.com/docs/examples/sqsqueue/set_queue_attributes.phps
	 */
	public function set_queue_attributes($opt = null)
	{
		if ($this->queue_url)
		{
			return parent::set_queue_attributes($this->queue_url, $opt);
		}

		throw new SQSQueue_Exception(SQSQUEUE_DEFAULT_ERROR);
	}


	/*%******************************************************************************************%*/
	// MESSAGES

	/**
	 * Method: send_message()
	 * 	Identical to <AmazonSQS::send_message()>, except that you don't need to pass in a queue URL.
	 *
	 * Access:
	 * 	public
	 *
	 * Parameters:
	 * 	message - See <AmazonSQS::send_message()>.
	 * 	returnCurlHandle - See <AmazonSQS::send_message()>.
	 *
	 * Returns:
	 * 	<ResponseCore> object
 	 *
	 * See Also:
	 * 	Example Usage - http://getcloudfusion.com/docs/examples/sqsqueue/send_message.phps
	 */
	public function send_message($message, $returnCurlHandle = null)
	{
		if ($this->queue_url)
		{
			return parent::send_message($this->queue_url, $message, $returnCurlHandle);
		}

		throw new SQSQueue_Exception(SQSQUEUE_DEFAULT_ERROR);
	}

	/**
	 * Method: receive_message()
	 * 	Identical to <AmazonSQS::receive_message()>, except that you don't need to pass in a queue URL.
	 *
	 * Access:
	 * 	public
	 *
	 * Parameters:
	 * 	opt - See <AmazonSQS::receive_message()>.
	 *
	 * Returns:
	 * 	<ResponseCore> object
 	 *
	 * See Also:
	 * 	Example Usage - http://getcloudfusion.com/docs/examples/sqsqueue/receive_message.phps
	 */
	public function receive_message($opt = null)
	{
		if ($this->queue_url)
		{
			return parent::receive_message($this->queue_url, $opt);
		}

		throw new SQSQueue_Exception(SQSQUEUE_DEFAULT_ERROR);
	}

	/**
	 * Method: delete_message()
	 * 	Identical to <AmazonSQS::delete_message()>, except that you don't need to pass in a queue URL.
	 *
	 * Access:
	 * 	public
	 *
	 * Parameters:
	 * 	receipt_handle - See <AmazonSQS::delete_message()>.
	 * 	returnCurlHandle - See <AmazonSQS::delete_message()>.
	 *
	 * Returns:
	 * 	<ResponseCore> object
 	 *
	 * See Also:
	 * 	Example Usage - http://getcloudfusion.com/docs/examples/sqsqueue/delete_message.phps
	 */
	public function delete_message($receipt_handle, $returnCurlHandle = null)
	{
		if ($this->queue_url)
		{
			return parent::delete_message($this->queue_url, $receipt_handle, $returnCurlHandle);
		}

		throw new SQSQueue_Exception(SQSQUEUE_DEFAULT_ERROR);
	}

	/**
	 *
	 */
	public function change_message_visibility()
	{

	}


	/*%******************************************************************************************%*/
	// ACCESS CONTROL METHODS

	// Inherit from parent class
	// public function generate_policy() {}

	// Inherit from parent class
	// public function add_permission() {}

	// Inherit from parent class
	// public function remove_permission() {}


	/*%******************************************************************************************%*/
	// HELPER/UTILITY METHODS

	/**
	 * Method: get_queue_size()
	 * 	Identical to <AmazonSQS::get_queue_size()>, except that you don't need to pass in a queue URL.
	 *
	 * Access:
	 * 	public
	 *
	 * Returns:
	 * 	_integer_ The Approximate number of messages in the queue.
 	 *
	 * See Also:
	 * 	Example Usage - http://getcloudfusion.com/docs/examples/sqsqueue/get_queue_size.phps
	 */
	public function get_queue_size()
	{
		if ($this->queue_url)
		{
			return parent::get_queue_size($this->queue_url);
		}

		throw new SQSQueue_Exception(SQSQUEUE_DEFAULT_ERROR);
	}
}
