<?php

namespace Repack\Hashing;

use RuntimeException;

class ArgonHasher extends AbstractHasher
{
    /**
     * The default memory cost factor.
     *
     * @var int
     */
    protected $memory = 1024;

    /**
     * The default time cost factor.
     *
     * @var int
     */
    protected $time = 2;

    /**
     * The default threads factor.
     *
     * @var int
     */
    protected $threads = 2;

    /**
     * Indicates whether to perform an algorithm check.
     *
     * @var bool
     */
    protected $verifyAlgorithm = false;

    /**
     * Create a new hasher instance.
     *
     * @param  array  $options
     * @return void
     */
    public function __construct(array $options = array())
    {
        $this->time = isset($options['time']) ? $options['time'] : $this->time;
        $this->memory = isset($options['memory']) ? $options['memory'] : $this->memory;
        $this->threads = isset($options['threads']) ? $options['threads'] : $this->threads;
        $this->verifyAlgorithm = isset($options['verify']) ? $options['verify'] : $this->verifyAlgorithm;
    }

    /**
     * Hash the given value.
     *
     * @param  string  $value
     * @param  array  $options
     * @return string
     *
     * @throws \RuntimeException
     */
    public function make($value, array $options = array())
    {
        $hash = password_hash($value, $this->algorithm(), array(
            'memory_cost' => $this->memory($options),
            'time_cost' => $this->time($options),
            'threads' => $this->threads($options),
        ));

        if ($hash === false) {
            throw new RuntimeException('Argon2 hashing not supported.');
        }

        return $hash;
    }

    /**
     * Get the algorithm that should be used for hashing.
     *
     * @return int
     */
    protected function algorithm()
    {
        return PASSWORD_ARGON2I;
    }

    /**
     * Check the given plain value against a hash.
     *
     * @param  string  $value
     * @param  string  $hashedValue
     * @param  array  $options
     * @return bool
     */
    public function check($value, $hashedValue, array $options = array())
    {
        if ($this->verifyAlgorithm && $this->info($hashedValue)['algoName'] !== 'argon2i') {
            throw new RuntimeException('This password does not use the Argon2i algorithm.');
        }

        return parent::check($value, $hashedValue, $options);
    }

    /**
     * Check if the given hash has been hashed using the given options.
     *
     * @param  string  $hashedValue
     * @param  array  $options
     * @return bool
     */
    public function needsRehash($hashedValue, array $options = array())
    {
        return password_needs_rehash($hashedValue, $this->algorithm(), array(
            'memory_cost' => $this->memory($options),
            'time_cost' => $this->time($options),
            'threads' => $this->threads($options),
        ));
    }

    /**
     * Set the default password memory factor.
     *
     * @param  int  $memory
     * @return $this
     */
    public function setMemory($memory)
    {
        $this->memory = (int) $memory;

        return $this;
    }

    /**
     * Set the default password timing factor.
     *
     * @param  int  $time
     * @return $this
     */
    public function setTime($time)
    {
        $this->time = (int) $time;

        return $this;
    }

    /**
     * Set the default password threads factor.
     *
     * @param  int  $threads
     * @return $this
     */
    public function setThreads($threads)
    {
        $this->threads = (int) $threads;

        return $this;
    }

    /**
     * Extract the memory cost value from the options array.
     *
     * @param  array  $options
     * @return int
     */
    protected function memory(array $options)
    {
        return isset($options['memory']) ? $options['memory'] : $this->memory;
    }

    /**
     * Extract the time cost value from the options array.
     *
     * @param  array  $options
     * @return int
     */
    protected function time(array $options)
    {
        return isset($options['time']) ? $options['time'] : $this->time;
    }

    /**
     * Extract the threads value from the options array.
     *
     * @param  array  $options
     * @return int
     */
    protected function threads(array $options)
    {
        return isset($options['threads']) ? $options['threads'] : $this->threads;
    }
}
