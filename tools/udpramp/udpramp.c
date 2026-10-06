// udpramp.c — generatore UDP a rampa deterministica, payload minimo (4 byte seq)
// build:  gcc -O3 -Wall -o udpramp udpramp.c -lrt
// usage:  sudo udpramp --src-ip 10.0.0.1 --dst-ip 10.0.0.2 \
//                     --src-port 5000 --dst-port 5000 \
//                     --payload 4 --cpu 2 \
//                     --ramp 20:1,10,100,1000,10000,100000

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define LIKELY(x)    __builtin_expect(!!(x), 1)
#define UNLIKELY(x)  __builtin_expect(!!(x), 0)

#define MIN_PAYLOAD  4
#define MAX_PAYLOAD  1472

static volatile sig_atomic_t running = 1;
static void sig_handler(int s) { (void)s; running = 0; }

/* ---------------------- helper timespec ---------------------- */

static void timespec_add_ns(struct timespec *ts, long ns) {
    ts->tv_nsec += ns;
    while (ts->tv_nsec >= 1000000000L) { ts->tv_sec++; ts->tv_nsec -= 1000000000L; }
    while (ts->tv_nsec <  0)           { ts->tv_sec--; ts->tv_nsec += 1000000000L; }
}

static int timespec_before(const struct timespec *a, const struct timespec *b) {
    return a->tv_sec < b->tv_sec ||
           (a->tv_sec == b->tv_sec && a->tv_nsec < b->tv_nsec);
}

/* Busy-spin puro su clock_gettime(MONOTONIC): precisione ~ns su tutti i rate.
 * Costo: 100% CPU sul core pinato per l'intera durata della run.
 * Scelta deliberata: con il vecchio hybrid (clock_nanosleep + busy-spin 20us)
 * lo step a 100 pps mostrava std~100us perche' il jitter di sveglia del kernel
 * su intervalli ~10ms non era assorbito dal guard band di 20us. Con busy-spin
 * puro lo std del generatore scende sotto 1us su tutta la rampa. */
static void wait_until(const struct timespec *target) {
    struct timespec now;
    do { clock_gettime(CLOCK_MONOTONIC, &now); }
    while (timespec_before(&now, target));
}

/* ---------------------- checksum incrementale ---------------------- */

static inline unsigned short fold_csum(unsigned long sum) {
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

/* Somma dei word IP fissi (escludendo quelli indicati da exclude_mask). */
static unsigned long compute_base_ip_sum(const struct iphdr *iph,
                                         unsigned int exclude_mask) {
    const unsigned short *p = (const unsigned short *)iph;
    unsigned long sum = 0;
    for (int i = 0; i < 10; i++)
        if (!(exclude_mask & (1u << i))) sum += p[i];
    return sum;
}

/* ---------------------- template pacchetto ---------------------- */

typedef struct {
    char           buf[2048];
    int            total_len;
    int            payload_len;
    struct iphdr  *iph;
    struct udphdr *udph;
    char          *payload;
    unsigned long  base_ip_sum;
} pkt_tpl_t;

static pkt_tpl_t tpl;

static void build_template(uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port,
                           int payload_size)
{
    memset(tpl.buf, 0, sizeof(tpl.buf));
    tpl.iph         = (struct iphdr  *)tpl.buf;
    tpl.udph        = (struct udphdr *)(tpl.buf + sizeof(struct iphdr));
    tpl.payload     = tpl.buf + sizeof(struct iphdr) + sizeof(struct udphdr);
    tpl.payload_len = payload_size;
    tpl.total_len   = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size;

    tpl.udph->source = htons(src_port);
    tpl.udph->dest   = htons(dst_port);
    tpl.udph->len    = htons(sizeof(struct udphdr) + payload_size);
    tpl.udph->check  = 0; /* checksum UDP: 0 = non controllato (consentito per IPv4) */

    tpl.iph->ihl      = 5;
    tpl.iph->version  = 4;
    tpl.iph->tos      = 0;
    tpl.iph->tot_len  = htons(tpl.total_len);
    tpl.iph->id       = 0;            /* per-pacchetto */
    tpl.iph->frag_off = 0;
    tpl.iph->ttl      = 64;
    tpl.iph->protocol = IPPROTO_UDP;
    tpl.iph->check    = 0;
    tpl.iph->saddr    = src_ip;
    tpl.iph->daddr    = dst_ip;

    /* base sum: escludi word 2 (id, l'unico variabile) */
    tpl.base_ip_sum = compute_base_ip_sum(tpl.iph, 1u << 2);
}

/* Hot path: scrive seq nel payload, aggiorna id e checksum IP, invia. */
static inline ssize_t send_one(int sock, uint32_t seq, uint16_t ip_id,
                               const struct sockaddr_in *dst)
{
    uint32_t seq_be = htonl(seq);
    memcpy(tpl.payload, &seq_be, 4);

    tpl.iph->id    = htons(ip_id);
    tpl.iph->check = 0;
    const unsigned short *w = (const unsigned short *)tpl.iph;
    tpl.iph->check = fold_csum(tpl.base_ip_sum + w[2]);

    return sendto(sock, tpl.buf, tpl.total_len, 0,
                  (const struct sockaddr *)dst, sizeof(*dst));
}

/* ---------------------- parsing rampa ---------------------- */

typedef struct { int duration_sec; int rate; } ramp_step_t;

static ramp_step_t *parse_ramp(const char *spec, int *n_out) {
    if (!spec || !*spec) return NULL;
    char *copy = strdup(spec);
    if (!copy) return NULL;
    char *colon = strchr(copy, ':');
    if (!colon || colon == copy) { free(copy); return NULL; }
    *colon = '\0';
    int dur = atoi(copy);
    if (dur <= 0) { free(copy); return NULL; }
    char *rates = colon + 1;
    if (!*rates) { free(copy); return NULL; }
    int n = 1;
    for (char *p = rates; *p; p++) if (*p == ',') n++;
    ramp_step_t *steps = calloc(n, sizeof(*steps));
    if (!steps) { free(copy); return NULL; }
    int i = 0;
    char *tok = strtok(rates, ",");
    while (tok && i < n) {
        int r = atoi(tok);
        if (r <= 0) {
            fprintf(stderr, "[ERR] rate '%s' invalido\n", tok);
            free(steps); free(copy);
            return NULL;
        }
        steps[i].duration_sec = dur;
        steps[i].rate         = r;
        i++;
        tok = strtok(NULL, ",");
    }
    free(copy);
    *n_out = i;
    return steps;
}

/* ---------------------- real-time engine ---------------------- */

static void enable_realtime(int cpu) {
    if (mlockall(MCL_CURRENT | MCL_FUTURE) == -1) {
        perror("[ERR] mlockall (serve root)"); exit(1);
    }
    struct sched_param p;
    p.sched_priority = sched_get_priority_max(SCHED_FIFO);
    if (sched_setscheduler(0, SCHED_FIFO, &p) == -1) {
        perror("[ERR] sched_setscheduler"); exit(1);
    }
    if (cpu >= 0) {
        cpu_set_t s; CPU_ZERO(&s); CPU_SET(cpu, &s);
        if (sched_setaffinity(0, sizeof(s), &s) == -1)
            perror("[WARN] sched_setaffinity");
    }
    fprintf(stderr, "[+] Real-time engine attivo (SCHED_FIFO, mlockall, CPU=%d)\n", cpu);
}

/* ---------------------- main ---------------------- */

static void usage(const char *p) {
    fprintf(stderr,
        "Usage: sudo %s [opts] --ramp DUR:R1,R2,...,RN\n"
        "  --src-ip  IP   sorgente UDP            (default 10.0.0.1)\n"
        "  --dst-ip  IP   destinazione UDP        (default 10.0.0.2)\n"
        "  --src-port N   porta sorgente          (default 5000)\n"
        "  --dst-port N   porta destinazione      (default 5000)\n"
        "  --payload  N   byte di payload UDP     (default 4, min 4, max 1472)\n"
        "  --cpu     N    pin a core N            (default 2, -1 = no pin)\n"
        "  --ramp DUR:R1,R2,...,RN\n"
        "                 N step di DUR secondi, ognuno al rate Ri pps\n"
        "Esempio:\n"
        "  sudo %s --src-ip 10.0.0.1 --dst-ip 10.0.0.2 --dst-port 5000 \\\n"
        "          --payload 4 --cpu 2 --ramp 20:1,10,100,1000,10000,100000\n",
        p, p);
}

int main(int argc, char **argv) {
    const char *src_ip_s   = "10.0.0.1";
    const char *dst_ip_s   = "10.0.0.2";
    int         src_port   = 5000;
    int         dst_port   = 5000;
    int         payload    = 4;
    int         cpu        = 2;
    const char *ramp_spec  = NULL;

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--src-ip")   && i+1<argc) src_ip_s  = argv[++i];
        else if (!strcmp(argv[i], "--dst-ip")   && i+1<argc) dst_ip_s  = argv[++i];
        else if (!strcmp(argv[i], "--src-port") && i+1<argc) src_port  = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--dst-port") && i+1<argc) dst_port  = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--payload")  && i+1<argc) payload   = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--cpu")      && i+1<argc) cpu       = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--ramp")     && i+1<argc) ramp_spec = argv[++i];
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]); return 0;
        } else {
            fprintf(stderr, "[ERR] opzione sconosciuta: %s\n", argv[i]);
            usage(argv[0]); return 1;
        }
    }

    if (!ramp_spec) { usage(argv[0]); return 1; }
    if (payload < MIN_PAYLOAD || payload > MAX_PAYLOAD) {
        fprintf(stderr, "[ERR] --payload tra %d e %d\n", MIN_PAYLOAD, MAX_PAYLOAD);
        return 1;
    }

    int n_steps = 0;
    ramp_step_t *steps = parse_ramp(ramp_spec, &n_steps);
    if (!steps || n_steps <= 0) {
        fprintf(stderr, "[ERR] --ramp invalido (formato: DUR:R1,R2,...)\n");
        return 1;
    }

    enable_realtime(cpu);
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) { perror("socket (richiede root o CAP_NET_RAW)"); return 1; }
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL"); close(sock); return 1;
    }
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    uint32_t src_ip = inet_addr(src_ip_s);
    uint32_t dst_ip = inet_addr(dst_ip_s);
    build_template(src_ip, dst_ip,
                   (uint16_t)src_port, (uint16_t)dst_port, payload);

    struct sockaddr_in dst = {0};
    dst.sin_family      = AF_INET;
    dst.sin_port        = htons((uint16_t)dst_port);
    dst.sin_addr.s_addr = dst_ip;

    long total_sec = 0;
    for (int i = 0; i < n_steps; i++) total_sec += steps[i].duration_sec;

    fprintf(stderr, "========================================\n");
    fprintf(stderr, "  udpramp  %s:%d -> %s:%d\n",
            src_ip_s, src_port, dst_ip_s, dst_port);
    fprintf(stderr, "  payload UDP : %d byte\n", payload);
    fprintf(stderr, "  ramp        : %d step, totale %lds\n", n_steps, total_sec);
    fprintf(stderr, "  rates (pps) :");
    for (int i = 0; i < n_steps; i++) fprintf(stderr, " %d", steps[i].rate);
    fprintf(stderr, "\n========================================\n");

    /* Allineamento al prossimo secondo intero (riproducibilita') */
    struct timespec sync_ts;
    clock_gettime(CLOCK_MONOTONIC, &sync_ts);
    sync_ts.tv_nsec = 0;
    sync_ts.tv_sec += 1;
    wait_until(&sync_ts);

    uint32_t seq   = 0;
    uint16_t ip_id = 0;
    unsigned long sent = 0, errs = 0;
    struct timespec next = sync_ts;

    for (int i = 0; i < n_steps && running; i++) {
        long interval_ns = 1000000000L / steps[i].rate;
        struct timespec step_end = next;
        step_end.tv_sec += steps[i].duration_sec;

        unsigned long pre_sent = sent, pre_errs = errs;

        time_t t = time(NULL);
        struct tm tmv; localtime_r(&t, &tmv);
        char tb[16]; strftime(tb, sizeof(tb), "%H:%M:%S", &tmv);
        fprintf(stderr, "[%s] STEP %d/%d  rate=%d pps  dur=%ds  interval=%ldns\n",
                tb, i + 1, n_steps, steps[i].rate,
                steps[i].duration_sec, interval_ns);

        while (LIKELY(running)) {
            /* invia solo se il prossimo slot e' STRETTAMENTE prima di step_end:
             * cosi' in N secondi a R pps escono esattamente N*R pacchetti,
             * non N*R+1 (intervallo chiuso a destra). */
            if (UNLIKELY(!timespec_before(&next, &step_end))) break;

            wait_until(&next);
            ssize_t r = send_one(sock, seq, ip_id, &dst);
            if (UNLIKELY(r < 0)) {
                if (errno == ENOBUFS || errno == EAGAIN) {
                    errs++;
                } else {
                    perror("sendto"); running = 0; break;
                }
            } else {
                sent++;
            }
            seq++;
            ip_id++;
            timespec_add_ns(&next, interval_ns);
        }

        t = time(NULL); localtime_r(&t, &tmv);
        strftime(tb, sizeof(tb), "%H:%M:%S", &tmv);
        fprintf(stderr, "[%s]   end  sent=%lu (cum=%lu) errs=%lu (cum=%lu)\n",
                tb, sent - pre_sent, sent, errs - pre_errs, errs);

        /* allinea l'inizio del prossimo step a step_end (no drift cumulativo) */
        next = step_end;
    }

    close(sock);
    free(steps);
    fprintf(stderr, "========================================\n");
    fprintf(stderr, "  totale sent : %lu\n", sent);
    fprintf(stderr, "  totale errs : %lu\n", errs);
    fprintf(stderr, "========================================\n");
    return 0;
}
