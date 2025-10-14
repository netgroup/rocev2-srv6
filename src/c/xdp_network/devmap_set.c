// Build: cc -O2 -g devmap_set.c $(pkg-config --cflags --libs libbpf) -lelf -lz -o devmap_set
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static void die(const char *m){ perror(m); exit(1); }
static void usage(const char *p){
  fprintf(stderr,"Usage:\n"
    "  %s --map-id N --key K --if IFACE --prog-pinned /sys/fs/bpf/PROG\n"
    "  %s --map-pinned /sys/fs/bpf/DEVMAP --key K --if IFACE --prog-pinned /sys/fs/bpf/PROG\n", p, p);
}

int main(int argc,char **argv){
  const char *map_pin=NULL,*prog_pin=NULL,*ifarg=NULL; int map_id=-1; unsigned key=0;
  static struct option o[]={{"map-pinned",1,0,'m'},{"map-id",1,0,'i'},{"key",1,0,'k'},
                            {"if",1,0,'f'},{"prog-pinned",1,0,'p'},{0,0,0,0}};
  for(int c;(c=getopt_long(argc,argv,"",o,NULL))!=-1;){
    if(c=='m') map_pin=optarg; else if(c=='i') map_id=atoi(optarg);
    else if(c=='k') key=(unsigned)strtoul(optarg,NULL,0);
    else if(c=='f') ifarg=optarg; else if(c=='p') prog_pin=optarg; else { usage(argv[0]); return 1; }
  }
  if((!map_pin && map_id<0) || !ifarg || !prog_pin){ usage(argv[0]); return 1; }

  int map_fd = map_pin ? bpf_obj_get(map_pin) : bpf_map_get_fd_by_id((__u32)map_id);
  if(map_fd<0) die("open devmap");
  int prog_fd = bpf_obj_get(prog_pin); if(prog_fd<0) die("open prog (pinned)");

  unsigned ifindex=0; char *end=NULL; long n=strtol(ifarg,&end,10);
  if(end && *end=='\0') ifindex=(unsigned)n; else if(!(ifindex=if_nametoindex(ifarg))) { fprintf(stderr,"bad IFACE\n"); return 1; }

  struct bpf_map_info mi={0}; __u32 len=sizeof(mi);
  if(bpf_obj_get_info_by_fd(map_fd,&mi,&len)==0){
    if(mi.type!=BPF_MAP_TYPE_DEVMAP && mi.type!=BPF_MAP_TYPE_DEVMAP_HASH){ fprintf(stderr,"map not devmap\n"); return 1; }
    if(mi.value_size!=8){ fprintf(stderr,"devmap value_size=%u (need 8). Kernel <5.8?\n",mi.value_size); return 1; }
  }
  struct { __u32 ifindex; union { int fd; __u32 id; } bpf_prog; } val = { .ifindex=ifindex };
  val.bpf_prog.fd = prog_fd;  // kernel expects FD on update

  if(bpf_map_update_elem(map_fd,&key,&val,0)<0) die("map update (devmap)");
  printf("OK: key=%u -> ifindex=%u prog_fd=%d\n",key,ifindex,prog_fd);
  return 0;
}
