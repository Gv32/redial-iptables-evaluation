// sendpkts.c - sender deterministico di pacchetti pre-generati per il banco REDIAL
// -----------------------------------------------------------------------------
// Basato su udpramp.c (raw socket + IP_HDRINCL, busy-spin puro su CLOCK_MONOTONIC,
// SCHED_FIFO a priorita' massima, mlockall, CPU pinning).
//
// Differenza rispetto a udpramp: i pacchetti NON sono sintetizzati al volo, ma
// letti dai due CSV prodotti da gen_packets.py:
//   * --net1 FILE   vettore per net1 (dn = 10.0.1.0/24)
//   * --net2 FILE   vettore per net2 (d2 = 10.0.2.0/24)
// Ogni riga del CSV diventa un pacchetto IP+UDP gia' pronto in memoria (src/sport/
// dst/dport/payload presi ESATTAMENTE dal file). Si scorre il vettore in ordine
// e, arrivati all'ultimo pacchetto, si RICOMINCIA dal primo (wrap-around).
//
// Rampa a step come udpramp: --ramp DUR:R1,...,RN, dove Ri e' il rate TOTALE pps
// dello step. Lo split percentuale --split P1,P2 ripartisce quel totale fra net1
// e net2 (es. --ramp ...:800000 --split 50,50 -> 400k pps a net1 e 400k a net2).
//
// build:  gcc -O3 -Wall -o sendpkts sendpkts.c -lrt
// usage:  sudo ip netns exec SX ./sendpkts --net1 packets_net1.csv
//             --net2 packets_net2.csv --split 50,50 --cpu 2
//             --ramp 20:1,10,100,1000,10000,100000,400000,800000

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
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

#define MAX_LINE   16384
#define MAX_FIELDS 16

static volatile sig_atomic_t running = 1;
static void sig_handler(int s) { (void)s; running = 0; }

/* ---------------------- helper timespec (identici a udpramp) ---------------------- */

static void timespec_add_ns(struct timespec *ts, long ns) {
    ts->tv_nsec += ns;
    while (ts->tv_nsec >= 1000000000L) { ts->tv_sec++; ts->tv_nsec -= 1000000000L; }
    while (ts->tv_nsec <  0)           { ts->tv_sec--; ts->tv_nsec += 1000000000L; }
}

static int timespec_before(const struct timespec *a, const struct timespec *b) {
    return a->tv_sec < b->tv_sec ||
           (a->tv_sec == b->tv_sec && a->tv_nsec < b->tv_nsec);
}

static void wait_until(const struct timespec *target) {
    struct timespec now;
    do { clock_gettime(CLOCK_MONOTONIC, &now); }
    while (timespec_before(&now, target));
}

/* ---------------------- checksum IP ---------------------- */

static uint16_t ip_checksum(const void *data, int len) {
    const uint16_t *p = (const uint16_t *)data;
    unsigned long sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

/* ---------------------- vettori di pacchetti ---------------------- */

typedef struct {
    uint8_t *buf;    /* pacchetto IP+UDP completo, gia' pronto da inviare */
    int      len;    /* lunghezza totale in byte */
    uint32_t dst_ip; /* per la sockaddr di sendto (network order) */
    uint16_t dport;  /* solo informativo */
} packet_t;

typedef struct {
    packet_t *pkts;
    size_t    n;
    size_t    idx;   /* posizione corrente (wrap-around) */
    char      tag[8];
} vector_t;

/* split CSV preservando i campi vuoti (rule_id puo' essere vuoto). */
static int split_csv(char *line, char **out, int maxf) {
    int n = 0;
    char *p = line;
    out[n++] = p;
    for (; *p; p++) {
        if (*p == ',') {
            *p = '\0';
            if (n < maxf) out[n++] = p + 1;
        }
    }
    return n;
}

static int hex2bin(const char *hex, uint8_t *out, int maxlen) {
    int n = 0;
    while (hex[0] && hex[1] && n < maxlen) {
        if (!isxdigit((unsigned char)hex[0]) || !isxdigit((unsigned char)hex[1])) break;
        int hi = (hex[0] <= '9') ? hex[0]-'0' : (tolower(hex[0])-'a'+10);
        int lo = (hex[1] <= '9') ? hex[1]-'0' : (tolower(hex[1])-'a'+10);
        out[n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return n;
}

static void build_packet(packet_t *pk, uint32_t src_ip, uint16_t sport,
                         uint32_t dst_ip, uint16_t dport,
                         const uint8_t *payload, int plen, uint16_t ip_id) {
    int total = sizeof(struct iphdr) + sizeof(struct udphdr) + plen;
    uint8_t *buf = calloc(1, total);
    if (!buf) { perror("calloc"); exit(1); }
    struct iphdr  *iph  = (struct iphdr  *)buf;
    struct udphdr *udph = (struct udphdr *)(buf + sizeof(struct iphdr));
    uint8_t       *pl   = buf + sizeof(struct iphdr) + sizeof(struct udphdr);

    iph->ihl      = 5;
    iph->version  = 4;
    iph->tos      = 0;
    iph->tot_len  = htons(total);
    iph->id       = htons(ip_id);
    iph->frag_off = 0;
    iph->ttl      = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check    = 0;
    iph->saddr    = src_ip;
    iph->daddr    = dst_ip;

    udph->source = htons(sport);
    udph->dest   = htons(dport);
    udph->len    = htons(sizeof(struct udphdr) + plen);
    udph->check  = 0; /* checksum UDP 0 = non controllato (consentito su IPv4) */

    if (plen > 0) memcpy(pl, payload, plen);

    iph->check = ip_checksum(iph, sizeof(struct iphdr));

    pk->buf    = buf;
    pk->len    = total;
    pk->dst_ip = dst_ip;
    pk->dport  = dport;
}

/* Carica un CSV di gen_packets.py in un vettore di pacchetti.
 * Campi (split per virgola): seq,net,proto,src,sport,dst,dport,plen,verdict,
 *                            rule_id,label,payload_hex
 * Servono: src[3] sport[4] dst[5] dport[6] e payload_hex (ultimo campo). */
static void load_vector(const char *path, const char *tag, vector_t *v) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "[ERR] apertura %s: %s\n", path, strerror(errno)); exit(1); }

    size_t cap = 4096;
    v->pkts = malloc(cap * sizeof(packet_t));
    if (!v->pkts) { perror("malloc"); exit(1); }
    v->n = 0; v->idx = 0;
    snprintf(v->tag, sizeof(v->tag), "%s", tag);

    char line[MAX_LINE];
    char *fields[MAX_FIELDS];
    uint8_t payload[2048];
    uint16_t ip_id = 0;
    int first = 1;

    while (fgets(line, sizeof(line), f)) {
        size_t L = strlen(line);
        while (L && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = '\0';
        if (L == 0) continue;
        if (first) { first = 0; if (!strncmp(line, "seq,", 4)) continue; }

        int nf = split_csv(line, fields, MAX_FIELDS);
        if (nf < 7) continue;

        uint32_t src_ip = inet_addr(fields[3]);
        uint16_t sport  = (uint16_t)atoi(fields[4]);
        uint32_t dst_ip = inet_addr(fields[5]);
        uint16_t dport  = (uint16_t)atoi(fields[6]);
        const char *phex = fields[nf - 1];
        int plen = hex2bin(phex, payload, sizeof(payload));

        if (v->n == cap) {
            cap *= 2;
            v->pkts = realloc(v->pkts, cap * sizeof(packet_t));
            if (!v->pkts) { perror("realloc"); exit(1); }
        }
        build_packet(&v->pkts[v->n], src_ip, sport, dst_ip, dport,
                     payload, plen, ip_id++);
        v->n++;
    }
    fclose(f);
    if (v->n == 0) { fprintf(stderr, "[ERR] %s: nessun pacchetto caricato\n", path); exit(1); }
}

/* ---------------------- real-time engine (identico a udpramp) ---------------------- */

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

/* ---------------------- parsing rampa (identico a udpramp) ---------------------- */

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

/* ---------------------- main ---------------------- */

static void usage(const char *p) {
    fprintf(stderr,
        "Usage: sudo ip netns exec SX %s [opts] --ramp DUR:R1,...,RN\n"
        "  --net1 FILE     CSV vettore net1            (default packets_net1.csv)\n"
        "  --net2 FILE     CSV vettore net2            (default packets_net2.csv)\n"
        "  --split P1,P2   ripartizione %% net1/net2    (default 50,50)\n"
        "  --cpu  N        pin a core N                (default 2, -1 = no pin)\n"
        "  --epoch-file F  scrive l'epoch REALTIME di start (allineamento listener)\n"
        "  --dry-run       non invia (test logica/conteggi senza root/raw socket)\n"
        "  --ramp DUR:R1,...,RN\n"
        "                  N step di DUR secondi, ognuno al rate TOTALE Ri pps\n"
        "                  (lo split ripartisce Ri fra net1 e net2)\n"
        "Esempio (50/50 a 800k tot = 400k+400k):\n"
        "  sudo ip netns exec SX %s --net1 packets_net1.csv --net2 packets_net2.csv \\\n"
        "          --split 50,50 --cpu 2 --ramp 20:1,10,100,1000,10000,100000,400000,800000\n",
        p, p);
}

int main(int argc, char **argv) {
    const char *net1_path = "packets_net1.csv";
    const char *net2_path = "packets_net2.csv";
    const char *split_s   = "50,50";
    const char *ramp_spec = NULL;
    const char *epoch_file = NULL;
    int cpu = 2;
    int dry_run = 0;

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--net1")       && i+1<argc) net1_path  = argv[++i];
        else if (!strcmp(argv[i], "--net2")       && i+1<argc) net2_path  = argv[++i];
        else if (!strcmp(argv[i], "--split")      && i+1<argc) split_s    = argv[++i];
        else if (!strcmp(argv[i], "--cpu")        && i+1<argc) cpu        = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--ramp")       && i+1<argc) ramp_spec  = argv[++i];
        else if (!strcmp(argv[i], "--epoch-file") && i+1<argc) epoch_file = argv[++i];
        else if (!strcmp(argv[i], "--dry-run")) dry_run = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "[ERR] opzione sconosciuta: %s\n", argv[i]); usage(argv[0]); return 1; }
    }

    if (!ramp_spec) { usage(argv[0]); return 1; }

    /* split percentuale -> frazione di pacchetti destinati a net1 */
    double w1 = 0, w2 = 0;
    {
        char *copy = strdup(split_s);
        char *c = strchr(copy, ',');
        if (!c) { fprintf(stderr, "[ERR] --split formato P1,P2\n"); return 1; }
        *c = '\0';
        w1 = atof(copy); w2 = atof(c + 1);
        free(copy);
        if (w1 < 0 || w2 < 0 || (w1 + w2) <= 0) {
            fprintf(stderr, "[ERR] --split valori non validi\n"); return 1;
        }
    }
    double frac1 = w1 / (w1 + w2);

    int n_steps = 0;
    ramp_step_t *steps = parse_ramp(ramp_spec, &n_steps);
    if (!steps || n_steps <= 0) {
        fprintf(stderr, "[ERR] --ramp invalido (formato: DUR:R1,R2,...)\n"); return 1;
    }

    /* carica i due vettori */
    vector_t v1 = {0}, v2 = {0};
    if (frac1 > 0.0) load_vector(net1_path, "net1", &v1);
    if (frac1 < 1.0) load_vector(net2_path, "net2", &v2);

    int sock = -1;
    if (!dry_run) {
        enable_realtime(cpu);
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock < 0) { perror("socket (richiede root o CAP_NET_RAW)"); return 1; }
        int one = 1;
        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            perror("setsockopt IP_HDRINCL"); close(sock); return 1;
        }
        int sndbuf = 4 * 1024 * 1024;
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    } else {
        fprintf(stderr, "[+] DRY-RUN: nessun invio reale (test logica/conteggi)\n");
    }

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    long total_sec = 0;
    for (int i = 0; i < n_steps; i++) total_sec += steps[i].duration_sec;

    fprintf(stderr, "========================================\n");
    fprintf(stderr, "  sendpkts  net1=%s (%zu pkt)  net2=%s (%zu pkt)\n",
            net1_path, v1.n, net2_path, v2.n);
    fprintf(stderr, "  split       : %.4g%% net1 / %.4g%% net2  (frac1=%.4f)\n",
            100*frac1, 100*(1-frac1), frac1);
    fprintf(stderr, "  ramp        : %d step, totale %lds (rate = pps TOTALE/step)\n",
            n_steps, total_sec);
    fprintf(stderr, "  rates (pps) :");
    for (int i = 0; i < n_steps; i++) fprintf(stderr, " %d", steps[i].rate);
    fprintf(stderr, "\n========================================\n");

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port   = 0;

    /* allineamento al prossimo secondo intero (riproducibilita') */
    struct timespec sync_ts;
    clock_gettime(CLOCK_MONOTONIC, &sync_ts);
    sync_ts.tv_nsec = 0;
    sync_ts.tv_sec += 1;
    wait_until(&sync_ts);

    if (epoch_file) {
        struct timespec rt; clock_gettime(CLOCK_REALTIME, &rt);
        FILE *ef = fopen(epoch_file, "w");
        if (ef) { fprintf(ef, "%ld.%09ld\n", (long)rt.tv_sec, rt.tv_nsec); fclose(ef); }
    }

    unsigned long sent1 = 0, sent2 = 0, errs = 0;
    double acc = 0.0;
    struct timespec next = sync_ts;

    for (int i = 0; i < n_steps && running; i++) {
        long interval_ns = 1000000000L / steps[i].rate;
        struct timespec step_end = next;
        step_end.tv_sec += steps[i].duration_sec;

        unsigned long p1 = sent1, p2 = sent2, pe = errs;

        time_t t = time(NULL); struct tm tmv; localtime_r(&t, &tmv);
        char tb[16]; strftime(tb, sizeof(tb), "%H:%M:%S", &tmv);
        fprintf(stderr, "[%s] STEP %d/%d  rate_tot=%d pps  dur=%ds  interval=%ldns\n",
                tb, i + 1, n_steps, steps[i].rate, steps[i].duration_sec, interval_ns);

        while (LIKELY(running)) {
            if (UNLIKELY(!timespec_before(&next, &step_end))) break;
            wait_until(&next);

            acc += frac1;
            int use1;
            if (acc >= 1.0) { use1 = 1; acc -= 1.0; } else { use1 = 0; }
            vector_t *v = use1 ? &v1 : &v2;
            packet_t *pk = &v->pkts[v->idx];
            v->idx++; if (v->idx >= v->n) v->idx = 0;

            if (LIKELY(!dry_run)) {
                dst.sin_addr.s_addr = pk->dst_ip;
                ssize_t r = sendto(sock, pk->buf, pk->len, 0,
                                   (const struct sockaddr *)&dst, sizeof(dst));
                if (UNLIKELY(r < 0)) {
                    if (errno == ENOBUFS || errno == EAGAIN) { errs++; }
                    else { perror("sendto"); running = 0; break; }
                } else { if (use1) sent1++; else sent2++; }
            } else {
                if (use1) sent1++; else sent2++;
            }

            timespec_add_ns(&next, interval_ns);
        }

        t = time(NULL); localtime_r(&t, &tmv);
        strftime(tb, sizeof(tb), "%H:%M:%S", &tmv);
        fprintf(stderr, "[%s]   end  net1=%lu net2=%lu (tot=%lu)  errs=%lu\n",
                tb, sent1 - p1, sent2 - p2, (sent1 - p1) + (sent2 - p2), errs - pe);

        next = step_end; /* no drift cumulativo */
    }

    if (sock >= 0) close(sock);
    free(steps);
    fprintf(stderr, "========================================\n");
    fprintf(stderr, "  inviati net1 : %lu\n", sent1);
    fprintf(stderr, "  inviati net2 : %lu\n", sent2);
    fprintf(stderr, "  totale       : %lu\n", sent1 + sent2);
    fprintf(stderr, "  errori       : %lu\n", errs);
    fprintf(stderr, "========================================\n");
    return 0;
}
