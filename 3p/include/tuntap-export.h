
#ifndef TUNTAP_EXPORT_H
#define TUNTAP_EXPORT_H

#ifdef TUNTAP_STATIC_DEFINE
#  define TUNTAP_EXPORT
#  define TUNTAP_NO_EXPORT
#else
#  ifndef TUNTAP_EXPORT
#    ifdef tuntap_EXPORTS
        /* We are building this library */
#      define TUNTAP_EXPORT 
#    else
        /* We are using this library */
#      define TUNTAP_EXPORT 
#    endif
#  endif

#  ifndef TUNTAP_NO_EXPORT
#    define TUNTAP_NO_EXPORT 
#  endif
#endif

#ifndef TUNTAP_DEPRECATED
#  define TUNTAP_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef TUNTAP_DEPRECATED_EXPORT
#  define TUNTAP_DEPRECATED_EXPORT TUNTAP_EXPORT TUNTAP_DEPRECATED
#endif

#ifndef TUNTAP_DEPRECATED_NO_EXPORT
#  define TUNTAP_DEPRECATED_NO_EXPORT TUNTAP_NO_EXPORT TUNTAP_DEPRECATED
#endif

#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef TUNTAP_NO_DEPRECATED
#    define TUNTAP_NO_DEPRECATED
#  endif
#endif

#endif /* TUNTAP_EXPORT_H */
