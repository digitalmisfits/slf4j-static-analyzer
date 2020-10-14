> :warning: **This project has been archived**

This project reports slf4j log statements (info, warn, error) which use interpolation objects of types other than the following:

* primitives (boolean , byte , char , short , int , long , float and double)
* java.lang.Character
* java.lang.String
* java.lang.Boolean
* java.lang.Enum
* java.time.*
* java.util.UUID
* java.util.Currency
* java.util.Locale
* java.lang.Throwable (when level is ERROR or WARN)
* Subtypes of java.util.Collection\<E\> where E equals any previously named complex type

All `toString()` method invocations are reported except when called from:

* java.time.*
* java.util.UUID
* java.util.Currency
* java.util.Locale
* java.util.Date
* net.logstash.logback.marker.LogstashMarker

For example:
Log statements such as `log.info("Logging this object({})) fails", new Object()"`

