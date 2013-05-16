AC_PREREQ([2.59])

AC_INIT([nf_tbf], [1.00])

AC_CONFIG_SRCDIR([nf_tbf.c])
AC_CONFIG_AUX_DIR([.])

AC_CANONICAL_BUILD
AC_CANONICAL_HOST

if test "x${host_os}" != "xlinux-gnu"
then
  AC_MSG_ERROR([Host OS is not GNU/Linux])
fi

AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
m4_ifdef([AC_PROG_MKDIR_P], [AC_PROG_MKDIR_P],
         [AC_SUBST([MKDIR_P], ["\@S|@(INSTALL) -d"])])

kernel_ver=
AC_ARG_WITH([kernel],
  [AS_HELP_STRING([--with-kernel=PATH], 
                  [use the kernel development files in PATH])],
  [if ! test -d "${with_kernel}"
   then
     AC_MSG_ERROR([\
The path `${with_kernel}' @{:@specified via --with-kernel@:}@ is not \
a directory.])
   fi
   if test -f "${with_kernel}/Makefile" -a \
           -f "${with_kernel}/include/config/kernel.release"
   then
      kernel_ver=`cat "${with_kernel}/include/config/kernel.release"`
   else
     AC_MSG_ERROR([\
The directory `${with_kernel}' doesn't look like the root of a kernel \
build tree.])
   fi],
  [if test "x${build_alias}" != "x${host_alias}"
   then
     AC_MSG_ERROR([\
Cross-compiling, kernel build tree path autodetection disabled. \
Please use --with-kernel.])
   fi
   kernel_ver=`uname -r`
   if test -z "${kernel_ver}"
   then
     AC_MSG_ERROR([\
Couldn't get the kernel version through uname, use --with-kernel.])
   fi
   with_kernel=
   if test -d "/lib/modules/${kernel_ver}"
   then
     build_dir="/lib/modules/${kernel_ver}/build"
     if test -f "${build_dir}/Makefile" -a \
             -f "${build_dir}/include/config/kernel.release"
     then
         with_kernel="${build_dir}"
     fi
   fi
   if test -z "${with_kernel}"
   then
     AC_MSG_ERROR([\
Couldn't autodetect kernel build tree path, use --with-kernel.])
   fi
   kernel_ver=`cat "${with_kernel}/include/config/kernel.release"`
   if ! test "$?" = "0"
   then
     AC_MSG_ERROR([\
Couldn't autodetect kernel build tree path, use --with-kernel.])
   fi])

case "${kernel_ver}" in
  2.6.*|3.*)
    ;;
  *)
    AC_MSG_ERROR([Unsupported kernel version `${kernel_ver}'.])
    ;;
esac

linux_version_h="${with_kernel}/include/linux/version.h"
if ! test -f "${linux_version_h}"
then
  linux_version_h="${with_kernel}/include/generated/uapi/linux/version.h"
  if ! test -f "${linux_version_h}"
  then
    AC_MSG_ERROR([\
Could not locate linux/version.h header in `${with_kernel}'])
  fi
fi

AC_PREPROC_IFELSE(
  [AC_LANG_PROGRAM([
#include "${linux_version_h}"
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
# error "Only 2.6.32+ kernels are supported."
#endif], [])],
  [], [AC_MSG_ERROR([Only 2.6.32+ kernels are supported.])])

AC_MSG_CHECKING([for configfs support])
AC_PREPROC_IFELSE(
  [AC_LANG_PROGRAM([
#include "${linux_version_h}"
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
# include "${with_kernel}/include/linux/autoconf.h"
#else
# include "${with_kernel}/include/generated/autoconf.h"
#endif
#if !defined(CONFIG_CONFIGFS_FS) && !defined(CONFIG_CONFIGFS_FS_MODULE)
# error "Configfs is disabled."
#endif], [])],
  [AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no])
   AC_MSG_ERROR([Configfs support is required.])])

AC_SUBST([KERNEL_DIR], [${with_kernel}])
AC_SUBST([KERNEL_VERSION], [${kernel_ver}])

AC_CONFIG_FILES([Makefile Kbuild])
AC_OUTPUT

