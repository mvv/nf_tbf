/*
 * Copyright (C) 2013 Mikhail Vorozhtsov
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "nf_tbf.h"

#define DEFAULT_CONFIGFS_PATH "/sys/kernel/config"

#define ARRAY_SIZE(ARRAY) (sizeof (ARRAY) / sizeof ((ARRAY)[0]))

static const char *argv_0;

#define ERROR(MSG,...) \
  fprintf (stderr, "%s: " MSG "\n", argv_0, ## __VA_ARGS__)

static const struct option options[] =
{
  { "configfs", 1, 0, 'c' },
  { "version", 0, 0, 'V' },
  { "help", 0, 0, 'H' },
  { 0, 0, 0, 0 }
};

static const struct option add_options[] =
{
  { "limit", 1, 0, 'l' },
  { "latency", 1, 0, 'L' },
  { "burst", 1, 0, 'b' },
  { "rate", 1, 0, 'r' },
  { 0, 0, 0, 0 }
};

static const struct option info_options[] =
{
  { "human-readable", 0, 0, 'h' },
  { "columns", 2, 0, 'c' },
  { 0, 0, 0, 0 }
};

static const struct option stats_options[] =
{
  { "human-readable", 0, 0, 'h' },
  { "columns", 2, 0, 'c' },
  { 0, 0, 0, 0 }
};

static void
usage ()
{
  printf ("\
Usage: nf_tbf_ctl [OPTIONS] [COMMAND]\n\
Options:\n\
  --configfs PATH\n\
      Path to the configfs mount point (defaults to `%s').\n\
  --version\n\
      Print the program version and exit.\n\
  --help\n\
      Print this message and exit.\n\
Commands:\n\
  list, ls              - List buckets.\n\
  add [OPTIONS] BUCKET  - Add a new bucket.\n\
    Options:\n\
      -l, --limit BYTES\n\
          Maximum queue size.\n\
      -L, --latency MS\n\
          Maximum amount of time a (high priority) packet can be held\n\
          in the queue.\n\
      -b, --burst BYTES\n\
          Number of bytes that can be sent instantaneously.\n\
      -r, --rate RATE\n\
          Maximum speed.\n\
  rm, del BUCKET         - Remove the bucket.\n\
  exists BUCKET          - Test if the bucket exists\n\
  configured BUCKET      - Test if the bucket is configured\n\
  info [OPTIONS] BUCKET  - Print the bucket configuration\n\
    Options:\n\
      -h, --human-readable\n\
          Print configuration in human readable format (default).\n\
      -c, --columns[=SETTINGS]\n\
          Print values of settings in SETTINGS separated by spaces.\n\
          SETTINGS defaults to `limit,latency,burst,rate'.\n\
  cfg [OPTIONS] BUCKET   - Reconfigure the bucket\n\
    Options:\n\
      -l, --limit BYTES\n\
          Maximum queue size.\n\
      -L, --latency MS\n\
          Maximum amount of time a (high priority) packet can be held\n\
          in the queue.\n\
      -b, --burst BYTES\n\
          Number of bytes that can be sent instantaneously.\n\
      -r, --rate RATE\n\
          Maximum speed.\n\
  stats [OPTIONS] BUCKET - Print the bucket counters\n\
    Options:\n\
      -h, --human-readable\n\
          Print counters in human readable format (default).\n\
      -c, --columns[=COUNTERS]\n\
          Print values of counters in COUNTERS separated by spaces.\n\
          COUNTERS defaults to `first_pkt_ts,pkts_bursted,bytes_bursted,\n\
          pkts_queued,bytes_queued,pkts_dropped,bytes_dropped,\n\
          pkts_nomem,bytes_nomem'.\n",
    DEFAULT_CONFIGFS_PATH);
}

static void
version ()
{
    printf ("nf_tbf_ctl %s\n", PACKAGE_VERSION);
}

static int
parse_uint32 (const char *str, uint32_t *result,
              uint32_t min_value, uint32_t max_value,
              const char **end)
{
  uint32_t value = 0;
  char c = *str;

  if (c < '0' || c > '9')
    return EINVAL;

  do
    {
      uint32_t d = c - '0';

      if (value > UINT32_MAX / 10
          || (value == UINT32_MAX / 10 && d > UINT32_MAX % 10))
        return ERANGE;

      value = value * 10 + d;

      if (value > max_value)
        return ERANGE;

      ++str;
      c = *str;
    }
  while (c >= '0' && c <= '9');

  if (value < min_value)
    return ERANGE;

  if (end)
    *end = str;
  else if (c)
    return EINVAL;

  *result = value;

  return 0;
}

static int
parse_size (const char *str, uint32_t *result)
{
  const char *end;
  uint32_t value;
  int r = parse_uint32(str, result, 0, UINT32_MAX, &end);

  if (r)
    return r;

  if (!*end)
    return 0;

  value = *result;

  if (!strcmp (end, "k"))
    {
      if (value > UINT32_MAX / 1000)
        return ERANGE;
      *result = value * 1000;
      return 0;
    }
  if (!strcmp (end, "m"))
    {
      if (value > UINT32_MAX / 1000000)
        return ERANGE;
      *result = value * 1000000;
      return 0;
    }
  if (!strcmp (end, "g"))
    {
      if (value > UINT32_MAX / 1000000000)
        return ERANGE;
      *result = value * 1000000000;
      return 0;
    }
  if (!strcmp (end, "K"))
    {
      if (value > UINT32_MAX / 1024)
        return ERANGE;
      *result = value * 1024;
      return 0;
    }
  if (!strcmp (end, "M"))
    {
      if (value > UINT32_MAX / (1024 * 1024))
        return ERANGE;
      *result = value * 1024 * 1024;
      return 0;
    }
  if (!strcmp (end, "G"))
    {
      if (value > UINT32_MAX / (1024 * 1024 * 1024))
        return ERANGE;
      *result = value * 1024 * 1024 * 1024;
      return 0;
    }

  return EINVAL;
}

static int
parse_uint64 (const char *str, uint64_t *result,
              uint64_t min_value, uint64_t max_value,
              const char **end)
{
  uint64_t value = 0;
  char c = *str;

  if (c < '0' || c > '9')
    return EINVAL;

  do
    {
      uint64_t d = c - '0';

      if (value > UINT64_MAX / 10
          || (value == UINT64_MAX / 10 && d > UINT64_MAX % 10))
        return ERANGE;

      value = value * 10 + d;

      if (value > max_value)
        return ERANGE;

      ++str;
      c = *str;
    }
  while (c >= '0' && c <= '9');

  if (value < min_value)
    return ERANGE;

  if (end)
    *end = str;
  else if (c)
    return EINVAL;

  *result = value;

  return 0;
}

static int
parse_rate (const char *str, uint32_t *result)
{
  const char *end;
  uint64_t value;
  int r = parse_uint64(str, &value, 0, UINT32_MAX * 8, &end);

  if (r)
    return r;

  if (!*end || !strcmp (end, "b") || !strcmp (end, "bps"))
    {
      *result = value >> 3;
      return 0;
    }
  if (!strcmp (end, "B") || !strcmp (end, "Bps"))
    {
      if (value > UINT32_MAX)
        return ERANGE;
      *result = value;
      return 0;
    }
  if (!strcmp (end, "k") || !strcmp (end, "kb") || !strcmp (end, "kbps"))
    {
      if (value > (UINT32_MAX * 8) / 1000)
        return ERANGE;
      *result = (value * 1000) >> 3;
      return 0;
    }
  if (!strcmp (end, "m") || !strcmp (end, "mb") || !strcmp (end, "mbps"))
    {
      if (value > (UINT32_MAX * 8) / 1000000)
        return ERANGE;
      *result = (value * 1000000) >> 3;
      return 0;
    }
  if (!strcmp (end, "g") || !strcmp (end, "gb") || !strcmp (end, "gbps"))
    {
      if (value > (UINT32_MAX * 8) / 1000000000)
        return ERANGE;
      *result = (value * 1000000000) >> 3;
      return 0;
    }
  if (!strcmp (end, "K") || !strcmp (end, "Kb") || !strcmp (end, "Kbps"))
    {
      if (value > (UINT32_MAX * 8) / 1024)
        return ERANGE;
      *result = (value * 1024) >> 3;
      return 0;
    }
  if (!strcmp (end, "M") || !strcmp (end, "Mb") || !strcmp (end, "Mbps"))
    {
      if (value > (UINT32_MAX * 8) / (1024 * 1024))
        return ERANGE;
      *result = (value * 1024 * 1024) >> 3;
      return 0;
    }
  if (!strcmp (end, "G") || !strcmp (end, "Gb") || !strcmp (end, "Gbps"))
    {
      if (value > (UINT32_MAX * 8) / (1024 * 1024 * 1024))
        return ERANGE;
      *result = (value * 1024 * 1024 * 1024) >> 3;
      return 0;
    }
  if (!strcmp (end, "kB") || !strcmp (end, "kBps"))
    {
      if (value > UINT32_MAX / 1000)
        return ERANGE;
      *result = value * 1000;
      return 0;
    }
  if (!strcmp (end, "mB") || !strcmp (end, "mBps"))
    {
      if (value > UINT32_MAX / 1000000)
        return ERANGE;
      *result = value * 1000000;
      return 0;
    }
  if (!strcmp (end, "gB") || !strcmp (end, "gBps"))
    {
      if (value > UINT32_MAX / 1000000000)
        return ERANGE;
      *result = value * 1000000000;
      return 0;
    }
  if (!strcmp (end, "KB") || !strcmp (end, "KBps"))
    {
      if (value > UINT32_MAX / 1024)
        return ERANGE;
      *result = value * 1024;
      return 0;
    }
  if (!strcmp (end, "MB") || !strcmp (end, "MBps"))
    {
      if (value > UINT32_MAX / (1024 * 1024))
        return ERANGE;
      *result = value * 1024 * 1024;
      return 0;
    }
  if (!strcmp (end, "GB") || !strcmp (end, "GBps"))
    {
      if (value > UINT32_MAX / (1024 * 1024 * 1024))
        return ERANGE;
      *result = value * 1024 * 1024 * 1024;
      return 0;
    }

  return -1;
}

static void
print_size (char *str, size_t len, uint32_t i)
{
  if (i == 1024)
    {
      snprintf (str, len, "1K");
      return;
    }
  if (i == 1000)
    {
      snprintf (str, len, "1k");
      return;
    }
  if (i < 1024)
    {
      snprintf (str, len, "%" PRIu32, i);
      return;
    }
  if (i % 1000 == 0)
    {
      i /= 1000;
      if (i % 1000 == 0)
        {
          i /= 1000;
          if (i % 1000 == 0)
            {
              i /= 1000;
              snprintf (str, len, "%" PRIu32 "g", i);
              return;
            }
          snprintf (str, len, "%" PRIu32 "m", i);
          return;
        }
      snprintf (str, len, "%" PRIu32 "k", i);
      return;
    }
  if (i % 1024 == 0)
    {
      i /= 1024;
      if (i % 1024 == 0)
        {
          i /= 1024;
          if (i % 1024 == 0)
            {
              i /= 1024;
              snprintf (str, len, "%" PRIu32 "G", i);
              return;
            }
          snprintf (str, len, "%" PRIu32 "M", i);
          return;
        }
      snprintf (str, len, "%" PRIu32 "K", i);
      return;
    }
  snprintf (str, len, "%" PRIu32, i);
}

int
main (int argc, char * const argv[])
{
  const char *configfs_path = DEFAULT_CONFIGFS_PATH;
  const char *cmd;
  char path[PATH_MAX];
  DIR *dir;
  uint16_t bucket_id;
  int c;

  argv_0 = argv[0];

  while (1)
    {
      c = getopt_long (argc, argv, "+", options, NULL);

      if (c == -1)
        break;

      switch (c)
        {
        case 'c':
          configfs_path = optarg;
          break;
        case 'V':
          version ();
          return 0;
        case 'H':
          usage ();
          return 0;
        default:
          return 1;
        }
    }

  argc -= optind;
  argv += optind;
  optind = 1;

  if (argc == 0)
    {
      ERROR ("A command expected.");
      return 1;
    }

#define OPEN_CONFIGFS_DIR                                                    \
  do                                                                         \
    {                                                                        \
      snprintf (path, sizeof (path), "%s/%s", configfs_path, PACKAGE_NAME);  \
                                                                             \
      dir = opendir (path);                                                  \
                                                                             \
      if (!dir)                                                              \
        {                                                                    \
          if (errno == ENOENT)                                               \
            ERROR (                                                          \
"Directory `%s' doesn't exist. Check that module `%s' is loaded "            \
"and configfs is mounted at `%s'.",                                          \
                   path, PACKAGE_NAME, configfs_path);                       \
          else                                                               \
            ERROR ("Failed to open directory `%s': %s.",                     \
                   path, strerror (errno));                                  \
                                                                             \
          return 2;                                                          \
        }                                                                    \
    }                                                                        \
  while (0)

#define CHECK_CONFIGFS_DIR                                                   \
  do                                                                         \
    {                                                                        \
      OPEN_CONFIGFS_DIR;                                                     \
      closedir (dir);                                                        \
    }                                                                        \
  while (0)

#define PARSE_BUCKET_ID                                                      \
  do                                                                         \
    {                                                                        \
      uint32_t bucket_id_value;                                              \
                                                                             \
      argv += optind;                                                        \
      argc -= optind;                                                        \
                                                                             \
      if (argc == 0)                                                         \
        {                                                                    \
          ERROR ("A bucket id expected.");                                   \
          return 1;                                                          \
        }                                                                    \
                                                                             \
      if (parse_uint32 (argv[0], &bucket_id_value, 0, 0xFFFF, NULL))         \
        {                                                                    \
          ERROR (                                                            \
"Invalid bucket id `%s', an integer between 0 and %u expected.",             \
                 argv[0], 0xFFFF);                                           \
          return 1;                                                          \
        }                                                                    \
                                                                             \
      bucket_id = bucket_id_value;                                           \
                                                                             \
      if (argc > 1)                                                          \
        {                                                                    \
          ERROR ("No arguments expected after bucket id.");                  \
          return 1;                                                          \
        }                                                                    \
    }                                                                        \
  while (0)

#define READ_ATTR(NAME,VALUE,RC_NOENT,RC_READ,RC_INVAL)                      \
  do                                                                         \
    {                                                                        \
      int fd;                                                                \
      ssize_t nread;                                                         \
                                                                             \
      snprintf (path, sizeof (path), "%s/%s/%u/" NAME,                       \
                configfs_path, PACKAGE_NAME, bucket_id);                     \
                                                                             \
      fd = open (path, O_RDONLY);                                            \
                                                                             \
      if (fd < 0)                                                            \
        {                                                                    \
          if (errno == ENOENT)                                               \
            {                                                                \
              ERROR ("Bucket #%u doesn't exist.", bucket_id);                \
              return (RC_NOENT);                                             \
            }                                                                \
                                                                             \
          ERROR ("Failed to read attribute `" NAME "': %s.",                 \
                 strerror (errno));                                          \
          return (RC_READ);                                                  \
        }                                                                    \
                                                                             \
      nread = read (fd, &(VALUE), sizeof (VALUE));                           \
                                                                             \
      if (nread < 0)                                                         \
        {                                                                    \
          ERROR ("Failed to read attribute `" NAME "': %s.",                 \
                 strerror (errno));                                          \
          return (RC_READ);                                                  \
        }                                                                    \
                                                                             \
      if (nread != sizeof (VALUE))                                           \
        {                                                                    \
          ERROR ("Failed to read attribute `" NAME "': %s.",                 \
                 strerror (errno));                                          \
          return (RC_INVAL);                                                 \
        }                                                                    \
                                                                             \
      close (fd);                                                            \
    }                                                                        \
  while (0)

#define WRITE_ATTR(NAME,VALUE,RC_NOENT,RC_WRITE)                             \
  do                                                                         \
    {                                                                        \
      int fd;                                                                \
                                                                             \
      snprintf (path, sizeof (path), "%s/%s/%u/" NAME,                       \
                configfs_path, PACKAGE_NAME, bucket_id);                     \
                                                                             \
      fd = open (path, O_WRONLY);                                            \
                                                                             \
      if (fd < 0)                                                            \
        {                                                                    \
          if (errno == ENOENT)                                               \
            {                                                                \
              ERROR ("Bucket #%u doesn't exist.", bucket_id);                \
              return (RC_NOENT);                                             \
            }                                                                \
                                                                             \
          ERROR ("Failed to write attribute `" NAME "': %s.",                \
                 strerror (errno));                                          \
          return (RC_WRITE);                                                 \
        }                                                                    \
                                                                             \
      if (write (fd, &(VALUE), sizeof (VALUE)) != sizeof (VALUE))            \
        {                                                                    \
          ERROR ("Failed to write attribute `" NAME "': %s.",                \
                 strerror (errno));                                          \
          return (RC_WRITE);                                                 \
        }                                                                    \
                                                                             \
      close (fd);                                                            \
    }                                                                        \
  while (0)

  cmd = argv[0];

  if (!strcmp (cmd, "list") || !strcmp (cmd, "ls"))
    {
      if (argc > 1)
        {
          ERROR ("No agruments expected for command `%s'.", cmd);
          return 1;
        }

      OPEN_CONFIGFS_DIR;

      while (1)
        {
          struct dirent *e;

          errno = 0;
          e = readdir (dir);

          if (e == NULL)
            {
              if (errno != 0)
                {
                  ERROR ("Failed to read pool list: %s.", strerror (errno));
                  return 3;
                }

              return 0;
            }

          if (e->d_name[0] >= '0' && e->d_name[0] <= '9')
            printf ("%s\n", e->d_name);
        }
    }
  else if (!strcmp (cmd, "add") || !strcmp (cmd, "cfg"))
    {
      struct nf_tbf_cfg cfg;
      uint32_t latency = 0;
      int r;

      memset (&cfg, 0, sizeof (cfg));

      ((const char **) argv)[0] = argv_0;
      
      while (1)
        {
          c = getopt_long (argc, argv, "+l:L:b:r:", add_options, NULL);

          if (c == -1)
            break;

          switch (c)
            {
            case 'l':
              r = parse_size (optarg, &cfg.limit);

              if (r == ERANGE)
                {
                  ERROR ("Limit `%s' is out of bounds.", optarg);
                  return 1;
                }
              if (r)
                {
                  ERROR ("Invalid limit `%s'.", optarg);
                  return 1;
                }
              if (cfg.limit == 0)
                {
                  ERROR ("Limit must be positive.");
                  return 1;
                }
              if (latency)
                latency = 0;
              break;
            case 'L':
              if (parse_uint32 (optarg, &latency, 0, 1000, NULL))
                {
                  ERROR ("\
Invalid latency `%s', an integer between 0 and 1000 expected.",
                         optarg);
                  return 1;
                }
              if (cfg.limit)
                cfg.limit = 0;
              break;
            case 'b':
              r = parse_size (optarg, &cfg.burst);

              if (r == ERANGE)
                {
                  ERROR ("Burst `%s' is out of bounds.", optarg);
                  return 1;
                }
              if (r)
                {
                  ERROR ("Invalid burst `%s'.", optarg);
                  return 1;
                }
              if (cfg.burst < NF_TBF_MIN_BURST)
                {
                  ERROR ("Burst must be greater or equal to %u.",
                         NF_TBF_MIN_BURST);
                  return 1;
                }

              break;
            case 'r':
              r = parse_rate (optarg, &cfg.rate);

              if (r == ERANGE)
                {
                  ERROR ("Rate `%s' is out of bounds.", optarg);
                  return 1;
                }
              if (r)
                {
                  ERROR ("Invalid rate `%s'.", optarg);
                  return 1;
                }
              if (cfg.rate < NF_TBF_MIN_RATE)
                {
                  ERROR ("Rate must be greater or equal to %uBps",
                         NF_TBF_MIN_RATE);
                  return 1;
                }

              break;
            default:
              return 1;
            }
        }

      if (cfg.burst == 0)
        {
          ERROR ("Burst was not specified.");
          return 1;
        }
      if (cfg.rate == 0)
        {
          ERROR ("Rate was not specified.");
          return 1;
        }
      if (cfg.limit == 0)
        {
          if (latency == 0)
            {
              ERROR ("Neither limit nor latency were specified.");
              return 1;
            }

          cfg.limit = ((uint64_t) latency * cfg.rate) / 1000;

          if (cfg.limit > UINT32_MAX - cfg.burst)
            {
              ERROR ("Latency is too high for the given rate and burst.");
              return 1;
            }

          cfg.limit += cfg.burst;
        }
      else if (cfg.limit < cfg.burst)
        {
          ERROR ("Limit must be greater or equal to burst.");
          return 1;
        }


      PARSE_BUCKET_ID;
      CHECK_CONFIGFS_DIR;

      if (!strcmp (cmd, "add"))
        {
          snprintf (path, sizeof (path), "%s/%s/%u",
                    configfs_path, PACKAGE_NAME, bucket_id);

          if (mkdir (path, 00771) < 0)
            {
              if (errno == EEXIST)
                {
                  ERROR ("Bucket #%u already exists.", bucket_id);
                  return 3;
                }
              else
                {
                  ERROR ("Failed to create directory `%s': %s.",
                         path, strerror (errno));
                  return 4;
                }
            }
        }

      WRITE_ATTR("cfg", cfg, 5, 5);
    }
  else if (!strcmp (cmd, "rm") || !strcmp (cmd, "del"))
    {
      PARSE_BUCKET_ID;
      CHECK_CONFIGFS_DIR;

      snprintf (path, sizeof (path), "%s/%s/%u",
                configfs_path, PACKAGE_NAME, bucket_id);

      if (rmdir (path) < 0)
        {
          if (errno == ENOENT)
            {
              ERROR ("Bucket #%u doesn't exist.", bucket_id);
              return 3;
            }

          ERROR ("Failed to remove directory `%s': %s.",
                 path, strerror (errno));
          return 4;
        }
    }
  else if (!strcmp (cmd, "exists"))
    {
      struct stat stat_buf;

      PARSE_BUCKET_ID;
      CHECK_CONFIGFS_DIR;

      snprintf (path, sizeof (path), "%s/%s/%u",
                configfs_path, PACKAGE_NAME, bucket_id);

      if (stat (path, &stat_buf) < 0)
        {
          if (errno == ENOENT)
            return 3;

          ERROR ("Failed to open directory `%s': %s.",
                 path, strerror (errno));
          return 4;
        }

      if (!S_ISDIR (stat_buf.st_mode))
        {
          ERROR ("Failed to open directory `%s': %s",
                 path, strerror (ENOTDIR));
          return 4;
        }
    }
  else if (!strcmp (cmd, "configured"))
    {
      struct nf_tbf_cfg cfg;

      PARSE_BUCKET_ID;
      CHECK_CONFIGFS_DIR;
      READ_ATTR("cfg", cfg, 3, 4, 4);

      if (cfg.burst == 0)
        return 5;
    }
  else if (!strcmp (cmd, "info"))
    {
      enum column
      {
        COLUMN_NONE = 0,
        COLUMN_LIMIT = 1,
        COLUMN_LATENCY = 2,
        COLUMN_BURST = 4,
        COLUMN_RATE = 8,
        COLUMN_ALL = COLUMN_LIMIT | COLUMN_LATENCY | COLUMN_BURST
                     | COLUMN_RATE
      };

      int human_readable_p = 1;
      enum column columns = COLUMN_ALL;
      enum column column_list[] = {
          COLUMN_LIMIT, COLUMN_LATENCY, COLUMN_BURST, COLUMN_RATE
        };

      struct nf_tbf_cfg cfg;
      uint64_t latency = 0, rem;

      ((const char **) argv)[0] = argv_0;

      while (1)
        {
          c = getopt_long (argc, argv, "+hc::", info_options, NULL);

          if (c == -1)
            break;

          switch (c)
            {
            case 'h':
              human_readable_p = 1;
              columns = COLUMN_ALL;
              column_list[0] = COLUMN_LIMIT;
              column_list[1] = COLUMN_LATENCY;
              column_list[2] = COLUMN_BURST;
              column_list[3] = COLUMN_RATE;
              break;
            case 'c':
              if (optarg == NULL)
                {
                  columns = COLUMN_ALL;
                  column_list[0] = COLUMN_LIMIT;
                  column_list[1] = COLUMN_LATENCY;
                  column_list[2] = COLUMN_BURST;
                  column_list[3] = COLUMN_RATE;
                }
              else
                {
                  unsigned int i;
                  const char *s = optarg;

                  if (!*s)
                    {
                      ERROR ("Empty settings list.");
                      return 1;
                    }

                  columns = COLUMN_NONE;
                  column_list[0] = COLUMN_NONE;
                  column_list[1] = COLUMN_NONE;
                  column_list[2] = COLUMN_NONE;
                  column_list[3] = COLUMN_NONE;

                  for (i = 0; i < ARRAY_SIZE (column_list); ++ i)
                    {
#define CHECK_TOKEN(TOKEN,COLUMN)                                            \
                      if (!strncmp (s, (TOKEN), strlen (TOKEN)) == 0)        \
                        {                                                    \
                          s += strlen (TOKEN);                               \
                                                                             \
                          if (*s && *s != ',')                               \
                            break;                                           \
                                                                             \
                          if (columns & (COLUMN))                            \
                            {                                                \
                              ERROR ("Token `" TOKEN "' is duplicated.");    \
                              return 1;                                      \
                            }                                                \
                                                                             \
                          columns |= COLUMN;                                 \
                          column_list[i] = COLUMN;                           \
                                                                             \
                          if (!*s)                                           \
                            break;                                           \
                                                                             \
                          continue;                                          \
                        }

                      CHECK_TOKEN ("limit", COLUMN_LIMIT);
                      CHECK_TOKEN ("latency", COLUMN_LATENCY);
                      CHECK_TOKEN ("burst", COLUMN_BURST);
                      CHECK_TOKEN ("rate", COLUMN_RATE);
#undef CHECK_TOKEN

                      break;
                    }

                  if (*s)
                    {
                      ERROR ("Invalid settings list `%s'.", optarg);
                      return 1;
                    }
                }

              human_readable_p = 0;
              break;
            default:
              return 1;
            }
        }

      PARSE_BUCKET_ID;
      CHECK_CONFIGFS_DIR;
      READ_ATTR("cfg", cfg, 3, 4, 5);

      if (cfg.rate > 0 && cfg.limit > cfg.burst) {
        latency = (uint64_t) (cfg.limit - cfg.burst) * 1000;
        rem = latency % cfg.rate;
        latency /= cfg.rate;
        latency += rem ? 1 : 0;
      }

      if (human_readable_p)
        {
          if (cfg.burst == 0)
            printf ("Bucket is not configured\n");
          else
            {
              char limit_str[20];
              char burst_str[20];
              char rate_str[20];
              print_size (limit_str, sizeof (limit_str), cfg.limit);
              print_size (burst_str, sizeof (burst_str), cfg.burst);
              print_size (rate_str, sizeof (rate_str), cfg.rate);
              printf ("\
Bucket limit: %s\n\
Bucket latency: %" PRIu64 "ms\n\
Bucket burst: %s\n\
Bucket rate: %sBps\n",
                limit_str, latency, burst_str, rate_str);
            }
        }
      else
        {
          unsigned int i;

          for (i = 0; i < ARRAY_SIZE (column_list); ++i)
            {
              enum column c = column_list[i];

              if (c == COLUMN_NONE)
                continue;

              if (i > 0)
                putchar (' ');

              switch (c)
                {
                  case COLUMN_LIMIT:
                    printf ("%" PRIu32, cfg.limit);
                    break;
                  case COLUMN_LATENCY:
                    printf ("%" PRIu64, latency);
                    break;
                  case COLUMN_BURST:
                    printf ("%" PRIu32, cfg.burst);
                    break;
                  case COLUMN_RATE:
                    printf ("%" PRIu32, cfg.rate);
                    break;
                  default:
                    break;
                }
            }

          putchar ('\n');
        }
    }
  else if (!strcmp (cmd, "stats"))
    {
      enum column
      {
        COLUMN_NONE = 0,
        COLUMN_FIRST_PKT_TS = 1,
        COLUMN_PKTS_BURSTED = 2,
        COLUMN_BYTES_BURSTED = 4,
        COLUMN_PKTS_QUEUED = 8,
        COLUMN_BYTES_QUEUED = 16,
        COLUMN_PKTS_DROPPED = 32,
        COLUMN_BYTES_DROPPED = 64,
        COLUMN_PKTS_NOMEM = 128,
        COLUMN_BYTES_NOMEM = 256,
        COLUMN_ALL = COLUMN_FIRST_PKT_TS
                     | COLUMN_PKTS_BURSTED | COLUMN_BYTES_BURSTED
                     | COLUMN_PKTS_QUEUED | COLUMN_BYTES_QUEUED
                     | COLUMN_PKTS_DROPPED | COLUMN_BYTES_DROPPED
                     | COLUMN_PKTS_NOMEM | COLUMN_BYTES_NOMEM
      };

      int human_readable_p = 1;
      enum column columns = COLUMN_ALL;
      enum column column_list[] = {
          COLUMN_FIRST_PKT_TS,
          COLUMN_PKTS_BURSTED, COLUMN_BYTES_BURSTED,
          COLUMN_PKTS_QUEUED, COLUMN_BYTES_QUEUED,
          COLUMN_PKTS_DROPPED, COLUMN_BYTES_DROPPED,
          COLUMN_PKTS_NOMEM, COLUMN_BYTES_NOMEM
        };

      struct nf_tbf_stats stats;

      ((const char **) argv)[0] = argv_0;

      while (1)
        {
          c = getopt_long (argc, argv, "+hc::", stats_options, NULL);

          if (c == -1)
            break;

          switch (c)
            {
            case 'h':
              human_readable_p = 1;
              columns = COLUMN_ALL;
              column_list[0] = COLUMN_FIRST_PKT_TS;
              column_list[1] = COLUMN_PKTS_BURSTED;
              column_list[2] = COLUMN_BYTES_BURSTED;
              column_list[3] = COLUMN_PKTS_QUEUED;
              column_list[4] = COLUMN_BYTES_QUEUED;
              column_list[5] = COLUMN_PKTS_DROPPED;
              column_list[6] = COLUMN_BYTES_DROPPED;
              column_list[7] = COLUMN_PKTS_NOMEM;
              column_list[8] = COLUMN_BYTES_NOMEM;
              break;
            case 'c':
              if (optarg == NULL)
                {
                  columns = COLUMN_ALL;
                  column_list[0] = COLUMN_FIRST_PKT_TS;
                  column_list[1] = COLUMN_PKTS_BURSTED;
                  column_list[2] = COLUMN_BYTES_BURSTED;
                  column_list[3] = COLUMN_PKTS_QUEUED;
                  column_list[4] = COLUMN_BYTES_QUEUED;
                  column_list[5] = COLUMN_PKTS_DROPPED;
                  column_list[6] = COLUMN_BYTES_DROPPED;
                  column_list[7] = COLUMN_PKTS_NOMEM;
                  column_list[8] = COLUMN_BYTES_NOMEM;
                }
              else
                {
                  unsigned int i;
                  const char *s = optarg;

                  if (!*s)
                    {
                      ERROR ("Empty counter list.");
                      return 1;
                    }

                  columns = COLUMN_NONE;
                  column_list[0] = COLUMN_NONE;
                  column_list[1] = COLUMN_NONE;
                  column_list[2] = COLUMN_NONE;
                  column_list[3] = COLUMN_NONE;
                  column_list[4] = COLUMN_NONE;
                  column_list[5] = COLUMN_NONE;
                  column_list[6] = COLUMN_NONE;
                  column_list[7] = COLUMN_NONE;
                  column_list[8] = COLUMN_NONE;

                  for (i = 0; i < ARRAY_SIZE (column_list); ++ i)
                    {
#define CHECK_TOKEN(TOKEN,COLUMN)                                            \
                      if (!strncmp (s, (TOKEN), strlen (TOKEN)) == 0)        \
                        {                                                    \
                          s += strlen (TOKEN);                               \
                                                                             \
                          if (*s && *s != ',')                               \
                            break;                                           \
                                                                             \
                          if (columns & (COLUMN))                            \
                            {                                                \
                              ERROR ("Token `" TOKEN "' is duplicated.");    \
                              return 1;                                      \
                            }                                                \
                                                                             \
                          columns |= COLUMN;                                 \
                          column_list[i] = COLUMN;                           \
                                                                             \
                          if (!*s)                                           \
                            break;                                           \
                                                                             \
                          continue;                                          \
                        }

                      CHECK_TOKEN ("first_pkt_ts", COLUMN_FIRST_PKT_TS);
                      CHECK_TOKEN ("pkts_bursted", COLUMN_PKTS_BURSTED);
                      CHECK_TOKEN ("bytes_bursted", COLUMN_BYTES_BURSTED);
                      CHECK_TOKEN ("pkts_queued", COLUMN_PKTS_QUEUED);
                      CHECK_TOKEN ("bytes_queued", COLUMN_BYTES_QUEUED);
                      CHECK_TOKEN ("pkts_dropped", COLUMN_PKTS_DROPPED);
                      CHECK_TOKEN ("bytes_dropped", COLUMN_BYTES_DROPPED);
                      CHECK_TOKEN ("pkts_nomem", COLUMN_PKTS_NOMEM);
                      CHECK_TOKEN ("bytes_nomem", COLUMN_BYTES_NOMEM);
#undef CHECK_TOKEN

                      break;
                    }

                  if (*s)
                    {
                      ERROR ("Invalid counter list `%s'.", optarg);
                      return 1;
                    }
                }

              human_readable_p = 0;
              break;
            default:
              return 1;
            }
        }

      PARSE_BUCKET_ID;
      CHECK_CONFIGFS_DIR;
      READ_ATTR("stats", stats, 3, 4, 5);

      if (human_readable_p)
        printf ("\
First packet timestamp: %" PRIu64 "\n\
Packets bursted: %" PRIu64 "\n\
Bytes bursted: %" PRIu64 "\n\
Packets queued: %" PRIu64 "\n\
Bytes queued: %" PRIu64 "\n\
Packets dropped: %" PRIu64 "\n\
Bytes dropped: %" PRIu64 "\n\
Packets lost: %" PRIu64 "\n\
Bytes lost: %" PRIu64 "\n",
                stats.first_pkt_ts,
                stats.pkts_bursted, stats.bytes_bursted,
                stats.pkts_queued, stats.bytes_queued,
                stats.pkts_dropped, stats.bytes_dropped,
                stats.pkts_nomem, stats.bytes_nomem);
      else
        {
          unsigned int i;

          for (i = 0; i < ARRAY_SIZE (column_list); ++i)
            {
              enum column c = column_list[i];

              if (c == COLUMN_NONE)
                continue;

              if (i > 0)
                putchar (' ');

              switch (c)
                {
                  case COLUMN_FIRST_PKT_TS:
                    printf ("%" PRIu64, stats.first_pkt_ts);
                    break;
                  case COLUMN_PKTS_BURSTED:
                    printf ("%" PRIu64, stats.pkts_bursted);
                    break;
                  case COLUMN_BYTES_BURSTED:
                    printf ("%" PRIu64, stats.bytes_bursted);
                    break;
                  case COLUMN_PKTS_QUEUED:
                    printf ("%" PRIu64, stats.pkts_queued);
                    break;
                  case COLUMN_BYTES_QUEUED:
                    printf ("%" PRIu64, stats.bytes_queued);
                    break;
                  case COLUMN_PKTS_DROPPED:
                    printf ("%" PRIu64, stats.pkts_dropped);
                    break;
                  case COLUMN_BYTES_DROPPED:
                    printf ("%" PRIu64, stats.bytes_dropped);
                    break;
                  case COLUMN_PKTS_NOMEM:
                    printf ("%" PRIu64, stats.pkts_nomem);
                    break;
                  case COLUMN_BYTES_NOMEM:
                    printf ("%" PRIu64, stats.pkts_nomem);
                    break;
                  default:
                    break;
                }
            }

          putchar ('\n');
        }
    }
  else
    {
      ERROR ("Unknown command `%s'.", cmd);
      return 1;
    }

  return 0;
}
