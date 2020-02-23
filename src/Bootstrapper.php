<?php

namespace Repack\Hashing;

use ArrayAccess;

class Bootstrapper
{
    /**
     * The array of created "drivers".
     *
     * @var ArrayAccess
     */
    protected static $ioc;

    /**
     * The array of created "drivers".
     *
     * @var array
     */
    protected static $drivers = array();

    public static function bootstrap(ArrayAccess $ioc)
    {
        static::setIoc($ioc);

        $ioc->singleton('hash', function () use ($ioc) {
            $manager = new Bootstrapper;
            return $manager->setIoc($ioc);
        });

        $ioc->singleton('hash.driver', function () use ($ioc) {
            return $ioc['hash']->driver();
        });
    }

    /**
     * @return ArrayAccess
     */
    public static function getIoc()
    {
        return static::$ioc;
    }

    /**
     * @param ArrayAccess $ioc
     *
     * @return void
     */
    public static function setIoc(ArrayAccess $ioc)
    {
        static::$ioc = $ioc;
    }

    /**
     * Create an instance of the Bcrypt hash Driver.
     *
     * @return BcryptHasher
     */
    public static function createBcryptDriver()
    {
        return new BcryptHasher(isset(static::$ioc['config']['hashing.bcrypt']) ? static::$ioc['config']['hashing.bcrypt'] : array());
    }

    /**
     * Create an instance of the Argon2i hash Driver.
     *
     * @return ArgonHasher
     */
    public static function createArgonDriver()
    {
        return new ArgonHasher(isset(static::$ioc['config']['hashing.argon']) ? static::$ioc['config']['hashing.argon'] : array());
    }

    /**
     * Create an instance of the Argon2id hash Driver.
     *
     * @return Argon2IdHasher
     */
    public static function createArgon2idDriver()
    {
        return new Argon2IdHasher(isset(static::$ioc['config']['hashing.argon']) ? static::$ioc['config']['hashing.argon'] : array());
    }

    /**
     * Get information about the given hashed value.
     *
     * @param  string  $hashedValue
     * @return array
     */
    public static function info($hashedValue)
    {
        return static::driver()->info($hashedValue);
    }

    /**
     * Hash the given value.
     *
     * @param  string  $value
     * @param  array   $options
     * @return string
     */
    public static function make($value, array $options = array())
    {
        return static::driver()->make($value, $options);
    }

    /**
     * Check the given plain value against a hash.
     *
     * @param  string  $value
     * @param  string  $hashedValue
     * @param  array   $options
     * @return bool
     */
    public static function check($value, $hashedValue, array $options = array())
    {
        return static::driver()->check($value, $hashedValue, $options);
    }

    /**
     * Check if the given hash has been hashed using the given options.
     *
     * @param  string  $hashedValue
     * @param  array   $options
     * @return bool
     */
    public static function needsRehash($hashedValue, array $options = array())
    {
        return static::driver()->needsRehash($hashedValue, $options);
    }

    /**
     * Get all of the created "drivers".
     *
     * @return array
     */
    public static function getDrivers()
    {
        return static::$drivers;
    }

    /**
     * Get the default driver name.
     *
     * @return void
     */
    public static function getDefaultDriver()
    {
        return isset(static::$ioc['config']['hashing.driver']) ? static::$ioc['config']['hashing.driver'] : 'bcrypt';
    }

    /**
     * Get a driver instance.
     *
     * @param  string  $driver
     * @return mixed
     *
     * @throws \InvalidArgumentException
     */
    public function driver($driver = null)
    {
        $driver = $driver ?: static::getDefaultDriver();

        if (is_null($driver)) {
            throw new \InvalidArgumentException(sprintf('Unable to resolve NULL driver for [%s].', get_called_class()));
        }

        // If the given driver has not been created before, we will create the instances
        // here and cache it so we can return it next time very quickly. If there is
        // already a driver created by this name, we'll just return that instance.
        if (!isset(static::$drivers[$driver])) {
            static::$drivers[$driver] = static::createDriver($driver);
        }

        return static::$drivers[$driver];
    }

    /**
     * Create a new driver instance.
     *
     * @param  string  $driver
     * @return mixed
     *
     * @throws \InvalidArgumentException
     */
    protected static function createDriver($driver)
    {
        $method = 'create' . ucfirst($driver) . 'Driver';

        if (is_callable($cb = get_called_class() . '::' . $method)) {
            return call_user_func($cb, static::$ioc);
        }

        throw new \InvalidArgumentException("Driver [$driver] not supported.");
    }
}
