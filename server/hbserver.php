<?php

/**
 * A simple web proxy.
 *
 * @category Web
 * @package  Hb_server
 * @author   "Alejandro Llanes" <sombra.libre@gmail.com>
 * @license  BSD http://httpbin.org
 * @link     http://example.org
 */

// RESULTS WRAPPER

/**
 * A class for wrapper result.
 */

class Result
{
    private const   VALID_STATES = [true, false];
    private $Left;
    private $Right;
    private $Msg;

    /**
     * @return null
     * $state true|false
     */
    public function __construct($state, $data=null, $msg=null)
    {
        if (!in_array($state, self::VALID_STATES)) {
            throw new Exception("Invalid state value", 1);
        }
        $this->Left = $state;
        if (!is_null($data)) {
            $this->Right = $data;
        }
        if (!is_null($msg)) {
            $this->Msg = $msg;
        }
    }

    public static function New($state, $data=null, $msg=null)
    {
        return new Result($state, $data, $msg);
    }

    public function Left()
    {
        return $this->Left;
    }

    public function Right()
    {
        return $this->Right;
    }
    
    public function Msg()
    {
        return $this->Msg;
    }

    public function unwrap()
    {
        return $this->Right;
    }
}

# An attempt to implement a control macro
function abort_on_error($result)
{
    ($result->Left() === false) ? function () {
        echo $result->Msg();
        exit;
    }
    : $result->Right();
}

// REST API TOOLKIT

class MicroRestMethod
{
    public const GET        = "GET";
    public const HEAD       = "HEAD";
    public const POST       = "POST";
    public const PUT        = "PUT";
    public const DELETE     = "DELETE";
    public const CONNECT    = "CONNECT";
    public const OPTIONS    = "OPTIONS";
    public const TRACE      = "TRACE";
    public const PATCH      = "PATCH";
}

/**
 * object oriented
 * $api = new MicroRest();
 * $api->register(MicroRestMethod::GET, "/", function(){
 *  echo "hello world";
 * });
 *
 * static call
 * MicroRest::build()
 * ->register(MicroRestMethod::GET, "/", function(){
 *  echo "hello world";
 * });
 */
class MicroRest
{
    private $routes;
    private $callables;
    private $shm;

    public function __construct()
    {
    }

    public static function build()
    {
        return new MicroRest();
    }

    public function setupSession($session_id)
    {
        $shm = shm_attach(crc32($session_id), 2048, 0666);
        if ($shm) {
            $this->shm = $shm;
            return true;
        } else {
            return false;
        }
    }

    public function sessionStore($key, $value)
    {
        if (shm_has_var($this->shm, crc32($key))) {
            shm_remove_var($this->shm, crc32($key));
        }
        if (shm_put_var($this->shm, crc32($key), $value)) {
            return true;
        }
        return false;
    }

    public function sessionRetriv($key)
    {
        if (shm_has_var($this->shm, crc32($key))) {
            return shm_get_var($this->shm, crc32($key));
        }
        return false;
    }

    public function releaseSession()
    {
        shm_detach($this->shm);
    }

    public function destroySession()
    {
        shm_remove($this->shm);
    }

    public function register($method, $path, $function)
    {
        $method_container = null;
        if (isset($this->routes[$method])) {
            $method_container = $this->routes[$method];
        }
        $callable_name = md5($method . $path);
        $method_container[$path] = $callable_name;
        $this->callables[$callable_name] = ($function);
        $this->routes[$method] = $method_container;
        return $this;
    }

    public function deploy()
    {
        if (isset($_SERVER['REQUEST_METHOD'])) {
            $method = $_SERVER['REQUEST_METHOD'];
            $path   = $_SERVER['PATH_INFO'];
            $callable_name = md5($method . $path);
            $func = $this->callables[$callable_name];
            $newfunc = $func->bindTo($this, $this);
            $newfunc();
        }
    }
}

class MicroRestResponse
{
    private $headers;
    private $raw_response;
    private $response;

    public function __construct()
    {
    }
    public function setBody($key, $value)
    {
        $this->raw_response[$key] = $value;
        return $this;
    }
    public function setHeader($header, $value)
    {
        $this->headers[$header] = $value;
        return $this;
    }
    public function toJson()
    {
        $this->response = json_encode($this->raw_response);
        $this->headers['Content-Length'] = count(byte_str_encode($this->response));
        return $this;
    }
    public function write($resp_code=200)
    {
        http_response_code($resp_code);
        foreach ($this->headers as $h => $v) {
            header("${h}: ${v}");
        }
        echo $this->response;
    }
}

// BYTES - STRING FUNCTIONS


function binary2String($bin)
{
    $str = null;
    foreach ($bin as $b) {
        $str .= pack('H', dechex(bindec($b)));
    }
    return $str;
}

function byte_str_decode($byte_array)
{
    $strs = array_map("chr", $byte_array);
    return implode("", $strs);
}

function byte_str_encode($str)
{
    return array_values(unpack('C*', $str));
}

// ASYNC UTILS

function isPcntlForkAllowed()
{
    $result = true;
    // function exists
    if (!function_exists('pcntl_fork')) {
        $result = false;
    }
    // module loaded
    if (!in_array('pcntl', get_loaded_extensions())) {
        $result = false;
    }
    return $result;
}

function pcntlForkTest()
{
    $pid = pcntl_fork();
    if ($pid == -1) {
        return Result::New(false, null, "\nHb_server could not fork!!\n\r");
    } elseif ($pid) {
        pcntl_wait($status);
        return Result::New(true);
    } else {
        posix_kill(getmypid(), SIGKILL);
    }
}

function isProcOpenAllowed()
{
    // pending implementation
    //https://www.php.net/manual/en/function.proc-open.php
    return "not implemented";
}

function isforkSupported()
{
    // check wheter native fork library loaded or not
    if (isPcntlForkAllowed()) {
        if (pcntlForkTest()->Left()) {
            return true;
        }
    }
    return false;
}

function spawnDaemon($session_id)
{
    $pid = pcntl_fork();
    if ($pid === -1) {
        return Result::new(false, null, "\nHb_server Couldn't fork\n\r");
    } elseif ($pid) {
        return Result::new(true);
    }

    posix_setsid();
    daemonMain($session_id);
}

function daemonMain($session_id)
{
    $queue_writer_id = "${session_id}001";
    $queue_reader   = msg_get_queue("${session_id}000", 0600);
    $queue_writer   = msg_get_queue("${session_id}001", 0600);
    $queue_control  = msg_get_queue("${session_id}002", 0600);

    if (function_exists('cli_set_process_title')) {
        cli_set_process_title("Hb_server-master-".$session_id);
    }
    $pid = pcntl_fork();
    if ($pid === -1) {
        $response = ["r" => "Failed", "msg" => "Cannot fork the loop process."];
        msg_send($queue_writer, 1, strlen(serialize(json_encode($response))));
        msg_send($queue_writer, 2, json_encode($response));
        die("Couldn't fork daemon");
    } elseif ($pid) {
        //parent
        $sec2micro = 1000000;
        $wait_secs = 5;
        $kill = false;
        while (true) {
            usleep($sec2micro * $wait_secs);
            if (msg_stat_queue($queue_control)['msg_qnum'] > 0) {
                break;
            }
        }
        msg_receive($queue_control, 0, $msg_type, 64, $data_size, false, MSG_NOERROR, $err);
        msg_receive($queue_control, 2, $msg_type, unserialize($data_size), $data, false, MSG_IPC_NOWAIT, $err);
        $request = json_decode(unserialize($data));
        if (isset($request['method'])) {
            switch ($request['method']) {
                    case 'KILL':
                        $msg = ["method" => "DELETE"];
                        // sent a DELETE command before kill, just to ensure socket is closed
                        // order child to kill himself
                        msg_send($queue_reader, 1, strlen(serialize(json_encode($msg))));
                        msg_send($queue_reader, 2, json_encode($msg));
                        $msg = ["method" => "KILL"];
                        msg_send($queue_reader, 1, strlen(serialize(json_encode($msg))));
                        msg_send($queue_reader, 2, json_encode($msg));
                        sleep(2);
                        // ensure queues are closed
                        if (msg_queue_exists("${session_id}000")) {
                            msg_remove_queue($queue_reader);
                        }
                        if (msg_queue_exists("${session_id}001")) {
                            msg_remove_queue($queue_writer);
                        }
                        if (msg_queue_exists("${session_id}002")) {
                            msg_remove_queue($queue_control);
                        }
                        // kill itself
                        $kill = true;
                        break;
                    default:
                        break;
                }
        }
        // wait status from child
        pcntl_wait($status);
        // kill itself
        posix_kill(getmypid(), SIGKILL);
    } else {
        //child
        if (function_exists('cli_set_process_title')) {
            cli_set_process_title("Hb_server-child-".$session_id);
        }
        // create socket
        $rs = tcp_socket_create();
        if ($rs->Left()) {
            // return ready to rest api
            $response = ["r" => "ready"];
            // send size data
            msg_send($queue_writer, 1, strlen(serialize(json_encode($response))));
            // send data packet
            msg_send($queue_writer, 2, json_encode($response));
            // get socket instance
            $socket = null;
            $context = $rs->Right();
            $quit = false;
            // do loop for process incoming request
            do {
                msg_receive($queue_reader, 1, $msg_type, 64, $data_size, false, MSG_NOERROR, $err);
                if (unserialize($data_size) < 1) {
                    continue;
                }
                msg_receive($queue_reader, 2, $msg_type, unserialize($data_size), $data, false, MSG_IPC_NOWAIT, $err);
                $request = json_decode(unserialize($data), true);
                if (isset($request['method'])) {
                    switch ($request['method']) {
                                    case 'KILL':
                                        unset($r);
                                        // close opened socket
                                        if (is_resource($socket)) {
                                            tcp_socket_close($socket);
                                        }
                                        // remove active queues
                                        if (msg_queue_exists("${session_id}000")) {
                                            msg_remove_queue($queue_reader);
                                        }
                                        if (msg_queue_exists("${session_id}001")) {
                                            msg_remove_queue($queue_writer);
                                        }
                                        $quit = true;
                                        break;
                                    case 'CONNECT':
                                        unset($r);
                                        $addr = $request["addr"];
                                        $port = $request["port"];
                                        $r = tcp_socket_connect($context, $addr, $port);
                                        if ($r->Left()) {
                                            $response = ["r" => "OK"];
                                            $socket = $r->Right();
                                            if (isset($request["initial_data"]) && isset($request["initial_data_size"]) && $request["initial_data_size"] > 0) {
                                                $wr = tcp_socket_write($socket, $request["initial_data"]);
                                            }
                                            $fr = tcp_socket_recv($socket);
                                            $pass_file = "/tmp/$queue_writer_id.raw";
                                            if ($fr->Left() && count($fr->Right()) > 0) {
                                                $response = ["r" => "OK", "data_file" => $pass_file];
                                            }
                                            $response =json_encode($response);
                                            file_put_contents($pass_file, serialize($fr->Right()));
                                            @msg_send($queue_writer, 1, strlen(serialize($response)));
                                            msg_send($queue_writer, 2, $response, true, true, $msg_err);
                                            unset($fr);
                                        } else {
                                            $response = ["r" => "Fail", "msg" => $r->Msg()];
                                            @msg_send($queue_writer, 1, strlen(serialize(json_encode($response))));
                                            @msg_send($queue_writer, 2, json_encode($response));
                                        }
                                        break;
                                    case 'WRITE':
                                        unset($r);
                                        $data = $request['data_file'];
                                        $data = unserialize(file_get_contents($data));
                                        unlink($request['data_file']);
                                        $r = tcp_socket_write($socket, $data);
                                        if ($r->Left()) {
                                            $response = ["r" => "OK"];
                                            @msg_send($queue_writer, 1, strlen(serialize(json_encode($response))));
                                            @msg_send($queue_writer, 2, json_encode($response));
                                        } else {
                                            $response = ["r" => "Fail", "msg" => $r->Msg()];
                                            @msg_send($queue_writer, 1, strlen(serialize(json_encode($response))));
                                            @msg_send($queue_writer, 2, json_encode($response));
                                        }
                                        break;
                                    case 'READ':
                                        unset($r);
                                        $r = tcp_socket_recv($socket);
                                        $pass_file = "/tmp/$queue_writer_id.raw";
                                        if ($r->Left()) {
                                            if ($r->Left() && count($r->Right()) > 0) {
                                                $response = ["r" => "OK", "data_file" => $pass_file];
                                                file_put_contents($pass_file, serialize($r->Right()));
                                                @msg_send($queue_writer, 1, strlen(serialize(json_encode($response))));
                                                @msg_send($queue_writer, 2, json_encode($response));
                                            } else {
                                                $response = ["r" => "OK", "data" => "null"];
                                                @msg_send($queue_writer, 1, strlen(serialize(json_encode($response))));
                                                @msg_send($queue_writer, 2, json_encode($response));
                                            }
                                        } else {
                                            $response = ["r" => "Fail", "msg" => $r->Msg()];
                                            @msg_send($queue_writer, 1, strlen(serialize(json_encode($response))));
                                            @msg_send($queue_writer, 2, json_encode($response));
                                        }
                                        break;
                                    case 'DELETE':
                                        unset($r);
                                        $r = tcp_socket_close($socket);
                                        if ($r->Left()) {
                                            $response = ["r" => "OK"];
                                            @msg_send($queue_writer, 1, strlen(serialize(json_encode($response))));
                                            @msg_send($queue_writer, 2, json_encode($response));
                                        } else {
                                            $response = ["r" => "Fail", "msg" => $r->Msg()];
                                            @msg_send($queue_writer, 1, strlen(serialize(json_encode($response))));
                                            @msg_send($queue_writer, 2, json_encode($response));
                                        }
                                        $quit = true;
                                        break;
                                    default:
                                        break;
                                }
                }
                usleep(10);
            } while (!$quit);
            // kill itself
            posix_kill(getmypid(), SIGKILL);
        } else {
            $response = ["r" => "Failed", "msg" => "Couldn't create socket"];
            // send size data
            msg_send($queue_writer, 1, strlen(serialize(json_encode($response))));
            // send data packet
            msg_send($queue_writer, 2, json_encode($response));
            // kill itself
            posix_kill(getmypid(), SIGKILL);
        }
    }
}

// SOCKET FUNCTION
#![(PUT)]
function tcp_socket_create()
{
    $opts = array(
        'socket' => array(
            'tcp_nodelay' => true
        ),
    );
    $context = stream_context_create($opts);
    if (!is_resource($context)) {
        return Result::New(false, null, "\nHb_server cannot create Stream Context\n\r");
    }
    return Result::New(true, $context);
}

#![(PATCH)]
function tcp_socket_connect($context, $dst_addr, $dst_port)
{
    $host_endpoint = "tcp://${dst_addr}:${dst_port}";
    $socket = stream_socket_client($host_endpoint, $errno, $errstr, 30);
    stream_set_timeout($socket, 1);
    if (!is_resource($socket)) {
        return Result::New(false, null, "Hb_server $errstr ($errno)");
    }
    return Result::New(true, $socket);
}

#![(POST)]
function tcp_socket_write($socket, $data)
{
    $data = byte_str_decode($data);
    $status = fwrite($socket, $data, strlen($data));
    fflush($socket);
    return Result::New(true, $socket);
}

#![(GET)]
function tcp_socket_recv($socket, $size=16)
{
    $response_buffer = null;
    while (($buf = stream_get_contents($socket, -1, -1)) != false) {
        if (strlen($buf) > 0) {
            $response_buffer .= $buf;
            if (strlen($buf) < $size) {
                break;
            }
        }
    }
    $response_buffer = byte_str_encode($response_buffer);
    if (count($response_buffer) > 0) {
        return Result::New(true, $response_buffer);
    } else {
        return Result::New(true, []);
    }
}

#![(DELETE)]
function tcp_socket_close($socket)
{
    if (is_resource($socket)) {
        if (fclose($socket)) {
            return Result::New(true);
        } else {
            return Result::New(false, null, "\nHb_server Cannot close Stream\n\r");
        }
    }
    return Result::New(true);
}

class SocketStore
{
    private $_socket = null;

    public function __construct($socket)
    {
        $this->_socket = $socket;
    }

    public function getInstance($serialize=false)
    {
        if (!$serialize) {
            return $this;
        } else {
            return serialize($this);
        }
    }

    public function getSocket()
    {
        return $this->_socket;
    }
}

/**
 * MAIN
 * more spaguetti code
 */

$root_path = '/hbserver/stream/json';

MicroRest::build()
// ipcs -q|-m
// ipcrm --all=msg|shm
->register(MicroRestMethod::PUT, $root_path, function () {
    if (function_exists('gmp_random_bits')) {
        $session_id = gmp_random_bits(32);
    } else {
        $session_id = rand(1000000000, 9999999999);
    }
    if (!$this->setupSession($session_id)) {
        $r = new MicroRestResponse();
        $r->setHeader("Content-Type", "application/json");
        $r->setBody('r', byte_str_encode("Fail"))
            ->setBody('msg', byte_str_encode("cannot setup session"))
            ->setBody("d", byte_str_encode("null"))
            ->setBody("s", 0)
            ->toJson()
            ->write(500);
    }
    $queue_writer_id   = "${session_id}000";
    $queue_reader_id   = "${session_id}001";
    $queue_control_id  = "${session_id}002";
    $this->sessionStore('queue_control', $queue_control_id);
    $this->sessionStore('queue_reader', $queue_reader_id);
    $this->sessionStore('queue_writer', $queue_writer_id);
    $this->releaseSession();

    if (isforkSupported()) {
        $result = spawnDaemon($session_id);
        if (!$result->Left()) {
            $r = new MicroRestResponse();
            $r->setHeader("Content-Type", "application/json");
            $r->setBody('r', byte_str_encode("Fail"))
            ->setBody('msg', byte_str_encode($result->Msg()))
            ->setBody("d", byte_str_encode("null"))
            ->setBody("s", 0)
            ->toJson()
            ->write(500);
        }
        $break = false;
        do {
            if (msg_queue_exists($queue_reader_id)) {
                $queue_reader = msg_get_queue($queue_reader_id);
                $status = msg_receive($queue_reader, 1, $msg_type, 64, $data_size, false, MSG_NOERROR, $err);
                if ($status) {
                    $status = msg_receive($queue_reader, 2, $msg_type, unserialize($data_size), $data, false, MSG_NOERROR, $err);
                    $creation_state = json_decode(unserialize($data), true);
                    if ($status && isset($creation_state['r']) && $creation_state['r'] == "ready") {
                        $r = new MicroRestResponse();
                        $r->setHeader("Content-Type", "application/json");
                        $r->setHeader("Set-Cookie", $session_id ."; path=/");
                        $r->setBody('r', byte_str_encode("Ok"))
                        ->setBody('msg', byte_str_encode("null"))
                        ->setBody("d", byte_str_encode("null"))
                        ->setBody("s", 0)
                        ->toJson()
                        ->write(201);
                        $break = true;
                    } else {
                        $break = true;
                        $r = new MicroRestResponse();
                        $r->setHeader("Content-Type", "application/json");
                        $r->setBody('r', byte_str_encode("Fail"))
                        ->setBody('msg', byte_str_encode($creation_state['msg']))
                        ->setBody("d", byte_str_encode("null"))
                        ->setBody("s", 0)
                        ->toJson()
                        ->write(500);
                    }
                } else {
                    $break = true;
                    $r = new MicroRestResponse();
                    $r->setHeader("Content-Type", "application/json");
                    $r->setBody('r', byte_str_encode("Fail"))
                    ->setBody('msg', byte_str_encode("CREATE: cannot get the size of the ready message"))
                    ->setBody("d", byte_str_encode("null"))
                    ->setBody("s", 0)
                    ->toJson()
                    ->write(500);
                }
            }
            usleep(10);
        } while (!$break);
    } else {
        $r = new MicroRestResponse();
        $r->setHeader("Content-Type", "application/json");
        $r->setBody('r', byte_str_encode("Fail"))
        ->setBody('msg', byte_str_encode("CREATE: Cannot start daemon"))
        ->setBody("d", byte_str_encode("null"))
        ->setBody("s", 0)
        ->toJson()
        ->write(500);
    }
})
// connect socket
->register(MicroRestMethod::PATCH, $root_path, function () {
    $maxlength = $_SERVER["CONTENT_LENGTH"];
    $session_id = trim(explode(";", $_SERVER['HTTP_COOKIE'])[0]);
    $r = new MicroRestResponse();
    $r->setHeader("Content-Type", "application/json");
    
    $_PATCH = json_decode(str_replace("'", '"', file_get_contents('php://input', false, null, 0, $maxlength)), true);
    $dest = $_PATCH['d'];
    $dst_addr = null;
    if (isset($dest['a']['Domain'])) {
        $dst_addr = byte_str_decode($dest['a']['Domain']);//domain
    }
    if (isset($dest['a']['V4'])) {
        $dst_addr = implode('.', $dest['a']['V4']);//ip address version 4
    }
    /** TODO */
    /* if (isset($dest['V6'])){
    $dest_addr = implode('.', $dest['V6']);//ip address version 6
    } */
    $dst_port = $dest['p'];
    $this->setupSession($session_id);

    $queue_reader_id = $this->sessionRetriv("queue_reader");
    $queue_writer_id = $this->sessionRetriv("queue_writer");

    $this->releaseSession();

    if (msg_queue_exists($queue_reader_id) && msg_queue_exists($queue_writer_id)) {
        $queue_reader = msg_get_queue($queue_reader_id, 0600);
        $queue_writer = msg_get_queue($queue_writer_id, 0600);
        if (!is_resource($queue_reader) && !is_resource($queue_writer)) {
            $r->setBody('r', byte_str_encode("Fail"))
            ->setBody('msg', byte_str_encode("CONNECT: cannot retrieve message queues"))
            ->setBody("d", byte_str_encode("null"))
            ->setBody("s", 0)
            ->toJson()
            ->write(500);
        }
    }

    $request = [
        "method" => "CONNECT",
        "addr" => $dst_addr,
        "port" => $dst_port,
        "initial_data" => $_PATCH['i'],
        "initial_data_size" => $_PATCH['s']];
    if (msg_send($queue_writer, 1, strlen(serialize(json_encode($request))))) {
        if (msg_send($queue_writer, 2, json_encode($request))) {
            while (true) {
                usleep(1000);
                if (msg_stat_queue($queue_reader)['msg_qnum'] > 0) {
                    break;
                }
            }
            $status = msg_receive($queue_reader, 1, $msg_type, 64, $data_size, false, MSG_IPC_NOWAIT, $err);
            if ($status) {
                $status = msg_receive($queue_reader, 2, $msg_type, unserialize($data_size), $data, false, MSG_NOERROR, $err);
                $connection_state = json_decode(unserialize($data), true);
                if ($status && isset($connection_state['r']) && $connection_state['r'] == "OK") {
                    $quit = true;
                    $rdata = byte_str_encode("null");
                    $rdata_size = 0;
                    if (isset($connection_state['data_file'])) {
                        $rdata = unserialize(file_get_contents($connection_state['data_file']));
                        unlink($connection_state['data_file']);
                        $rdata_size = count($rdata);
                    }
                    $r->setBody('r', byte_str_encode("Ok"))
                                ->setBody('msg', byte_str_encode("null"))
                                ->setBody("d", $rdata)
                                ->setBody("s", $rdata_size)
                                ->toJson()
                                ->write(201);
                } else {
                    $r->setBody('r', byte_str_encode("Fail"))
                                ->setBody('msg', byte_str_encode("CONNECT: cannot read the response " . $connection_state['msg']))
                                ->setBody("d", byte_str_encode("null"))
                                ->setBody("s", 0)
                                ->toJson()
                                ->write(500);
                    $quit = true;
                }
            }
        } else {
            $r->setBody('r', byte_str_encode("Fail"))
                    ->setBody('msg', byte_str_encode("CONNECT: cannot write the connection addr and port"))
                    ->setBody("d", byte_str_encode("null"))
                    ->setBody("s", 0)
                    ->toJson()
                    ->write(500);
        }
    } else {
        $r->setBody('r', byte_str_encode("Fail"))
                ->setBody('msg', byte_str_encode("CONNECT: cannot pass the request size"))
                ->setBody("d", byte_str_encode("null"))
                ->setBody("s", 0)
                ->toJson()
                ->write(500);
    }
})
// write to socket
->register(MicroRestMethod::POST, $root_path, function () {
    $maxlength = $_SERVER["CONTENT_LENGTH"];
    $session_id = trim(explode(";", $_SERVER['HTTP_COOKIE'])[0]);
    $r = new MicroRestResponse();
    $r->setHeader("Content-Type", "application/json");
    $data = json_decode(str_replace("'", '"', file_get_contents('php://input', false, null, 0, $maxlength)), true);
    $stream_data = $data['d'];

    $this->setupSession($session_id);

    $queue_reader_id = $this->sessionRetriv("queue_reader");
    $queue_writer_id = $this->sessionRetriv("queue_writer");

    $this->releaseSession();

    if (msg_queue_exists($queue_reader_id) && msg_queue_exists($queue_writer_id)) {
        $queue_reader = msg_get_queue($queue_reader_id, 0600);
        $queue_writer = msg_get_queue($queue_writer_id, 0600);
        if (!is_resource($queue_reader) && !is_resource($queue_writer)) {
            $r->setBody('r', byte_str_encode("Fail"))
            ->setBody('msg', byte_str_encode("WRITE: cannot retrieve message queues"))
            ->setBody("d", byte_str_encode("null"))
            ->setBody("s", 0)
            ->toJson()
            ->write(500);
        }
    }
    $pass_file = "/tmp/$queue_reader_id.raw";
    file_put_contents($pass_file, serialize($stream_data));
    $request = ["method" => "WRITE", "data_file" => $pass_file ];

    if (msg_send($queue_writer, 1, strlen(serialize(json_encode($request))))) {
        if (msg_send($queue_writer, 2, json_encode($request))) {
            $quit = false ;
            do {
                while (true) {
                    usleep(1000);
                    if (msg_stat_queue($queue_reader)['msg_qnum'] > 0) {
                        break;
                    }
                }
                $status = msg_receive($queue_reader, 1, $msg_type, 64, $data_size, false, MSG_NOERROR, $err);
                if ($status) {
                    $status = msg_receive($queue_reader, 2, $msg_type, unserialize($data_size), $data, false, MSG_NOERROR, $err);
                    $connection_state = json_decode(unserialize($data), true);

                    if ($status && isset($connection_state['r']) && $connection_state['r'] == "OK") {
                        $quit = true;
                        $r->setBody('r', byte_str_encode("Ok"))
                                ->setBody('msg', byte_str_encode("null"))
                                ->setBody("d", byte_str_encode("null"))
                                ->setBody("s", 0)
                                ->toJson()
                                ->write(200);
                    } else {
                        $r->setBody('r', byte_str_encode("Fail"))
                                ->setBody('msg', byte_str_encode("WRITE: cannot read the response " . json_decode(unserialize($data), true)['msg']))
                                ->setBody("d", byte_str_encode("null"))
                                ->setBody("s", 0)
                                ->toJson()
                                ->write(500);
                        $quit = true;
                    }
                }
            } while (!$quit);
        } else {
            $r->setBody('r', byte_str_encode("Fail"))
                    ->setBody('msg', byte_str_encode("WRITE: cannot write the connection addr and port"))
                    ->setBody("d", byte_str_encode("null"))
                    ->setBody("s", 0)
                    ->toJson()
                    ->write(500);
        }
    } else {
        $r->setBody('r', byte_str_encode("Fail"))
                ->setBody('msg', byte_str_encode("WRITE: cannot pass the request size"))
                ->setBody("d", byte_str_encode("null"))
                ->setBody("s", 0)
                ->toJson()
                ->write(500);
    }
})// read
->register(MicroRestMethod::GET, $root_path, function () {
    $session_id = trim(explode(";", $_SERVER['HTTP_COOKIE'])[0]);
    $r = new MicroRestResponse();
    $r->setHeader("Content-Type", "application/json");

    $this->setupSession($session_id);

    $queue_reader_id = $this->sessionRetriv("queue_reader");
    $queue_writer_id = $this->sessionRetriv("queue_writer");

    $this->releaseSession();

    if (msg_queue_exists($queue_reader_id) && msg_queue_exists($queue_writer_id)) {
        $queue_reader = msg_get_queue($queue_reader_id, 0600);
        $queue_writer = msg_get_queue($queue_writer_id, 0600);
        if (!is_resource($queue_reader) && !is_resource($queue_writer)) {
            $r->setBody('r', byte_str_encode("Fail"))
            ->setBody('msg', byte_str_encode("READ: cannot retrieve message queues"))
            ->setBody("d", byte_str_encode("null"))
            ->setBody("s", 0)
            ->toJson()
            ->write(500);
        }
    }

    $request = ["method" => "READ"];

    if (msg_send($queue_writer, 1, strlen(serialize(json_encode($request))))) {
        if (msg_send($queue_writer, 2, json_encode($request))) {
            while (true) {
                usleep(1000);
                if (msg_stat_queue($queue_reader)['msg_qnum'] > 0) {
                    break;
                }
            }
            $quit = false ;
            do {
                $status = msg_receive($queue_reader, 1, $msg_type, 64, $data_size, false, MSG_NOERROR, $err);
                if ($status) {
                    $status = msg_receive($queue_reader, 2, $msg_type, unserialize($data_size), $data, false, MSG_NOERROR, $err);
                    $connection_state = json_decode(unserialize($data), true);

                    if ($status && isset($connection_state['r']) && $connection_state['r'] == "OK") {
                        if ($connection_state['data_file'] != "null") {
                            $rdata = byte_str_encode("null");
                            $rdata_size = 0;
                            $quit = true;
                            if (isset($connection_state['data_file'])) {
                                $rdata = unserialize(file_get_contents($connection_state['data_file']));
                                unlink($connection_state['data_file']);
                                $rdata_size = count($rdata);
                            }
                            $r->setBody('r', byte_str_encode("Ok"))
                                ->setBody('msg', byte_str_encode("null"))
                                ->setBody("d", $rdata)
                                ->setBody("s", $rdata_size)
                                ->toJson()
                                ->write(200);
                            break;
                        } else {
                            $quit = true;
                            $r->setBody('r', byte_str_encode("Ok"))
                                ->setBody('msg', byte_str_encode("null"))
                                ->setBody("d", byte_str_encode("null"))
                                ->setBody("s", 0)
                                ->toJson()
                                ->write(200);
                            break;
                        }
                    } else {
                        $r->setBody('r', byte_str_encode("Fail"))
                                ->setBody('msg', byte_str_encode("READ: cannot read the response " . json_decode(unserialize($data), true)['msg']))
                                ->setBody("d", byte_str_encode("null"))
                                ->setBody("s", 0)
                                ->toJson()
                                ->write(500);
                        $quit = true;
                        break;
                    }
                } else {
                    $quit = true;
                    $r->setBody('r', byte_str_encode("Fail"))
                            ->setBody('msg', byte_str_encode("READ: read the size of the response"))
                            ->setBody("d", byte_str_encode("null"))
                            ->setBody("s", 0)
                            ->toJson()
                            ->write(500);
                    break;
                }
            } while (!$quit);
        } else {
            $r->setBody('r', byte_str_encode("Fail"))
                    ->setBody('msg', byte_str_encode("READ: cannot write the connection addr and port"))
                    ->setBody("d", byte_str_encode("null"))
                    ->setBody("s", 0)
                    ->toJson()
                    ->write(500);
        }
    } else {
        $r->setBody('r', byte_str_encode("Fail"))
                ->setBody('msg', byte_str_encode("READ: cannot pass the request size"))
                ->setBody("d", byte_str_encode("null"))
                ->setBody("s", 0)
                ->toJson()
                ->write(500);
    }
})// delete
->register(MicroRestMethod::DELETE, $root_path, function () {
    $session_id = trim(explode(";", $_SERVER['HTTP_COOKIE'])[0]);
    $r = new MicroRestResponse();
    $r->setHeader("Content-Type", "application/json");

    $this->setupSession($session_id);

    $queue_control_id = $this->sessionRetriv("queue_control");

    if (msg_queue_exists($queue_control_id)) {
        $queue_control = msg_get_queue($queue_reader_id, 0600);
        $queue_writer = msg_get_queue($queue_writer_id, 0600);
        if (!is_resource($queue_control)) {
            $r->setBody('r', byte_str_encode("Fail"))
            ->setBody('msg', byte_str_encode("READ: cannot adquire control queue"))
            ->setBody("d", byte_str_encode("null"))
            ->setBody("s", 0)
            ->toJson()
            ->write(500);
        }
    }

    $request = ["method" => "KILL"];
    if (msg_send($queue_control, 1, strlen(serialize(json_encode($request))))) {
        if (msg_send($queue_control, 2, json_encode($request))) {
            $this->destroySession();
            $r->setBody('r', byte_str_encode("Ok"))
                                ->setBody('msg', byte_str_encode("null"))
                                ->setBody("d", byte_str_encode("null"))
                                ->setBody("s", 0)
                                ->toJson()
                                ->write(200);
        } else {
            $r->setBody('r', byte_str_encode("Fail"))
                    ->setBody('msg', byte_str_encode("DELETE: cannot write the kill command"))
                    ->setBody("d", byte_str_encode("null"))
                    ->setBody("s", 0)
                    ->toJson()
                    ->write(500);
        }
    } else {
        $r->setBody('r', byte_str_encode("Fail"))
                ->setBody('msg', byte_str_encode("DELETE: cannot pass the request size"))
                ->setBody("d", byte_str_encode("null"))
                ->setBody("s", 0)
                ->toJson()
                ->write(500);
    }
})
->deploy();
