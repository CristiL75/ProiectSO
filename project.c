#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/wait.h>
#include<stdio.h>

// Structura pentru metadatele fiecărui fișier/director
struct Metadata {
    char nume[256];
    char cale[512];
    char tip;  // 'F' pentru fișier, 'D' pentru director
    off_t marime; // Dimensiunea fișierului
    time_t ultimaModificare; // Data și ora ultimei modificări
};

// Funcție pentru a captura metadatele fiecărui fișier/director
void parsare_metadate(char *cale, struct Metadata *metadate) {
    struct stat stareFisier;

    if (stat(cale, &stareFisier) < 0)
        return;

    strcpy(metadate->nume, strrchr(cale, '/') + 1);
    strcpy(metadate->cale, cale);
    metadate->tip = (S_ISDIR(stareFisier.st_mode)) ? 'D' : 'F';
    metadate->marime = stareFisier.st_size;
    metadate->ultimaModificare = stareFisier.st_mtime;
}

void creaza_snapshot(char *dir_cale, char *snapshot_file, char *directorSpatiuIzolat, char *argv[]) {
    int fptr;
    struct Metadata metadate;
    DIR *dir;
    struct dirent *ent;

    // Verifică dacă directorul de snapshot-uri există, altfel îl creează
    struct stat st = {0};
    if (stat(argv[2], &st) == -1) {
        mkdir(argv[2], 0777);
    }

    if ((dir = opendir(dir_cale)) != NULL) {
        char snapshot_vechi[512], snapshot_nou[512];
        sprintf(snapshot_vechi, "%s/Snapshot_vechi.txt", argv[2]);
        sprintf(snapshot_nou, "%s/Snapshot_nou.txt", argv[2]);

        fptr = open(snapshot_nou, O_WRONLY | O_CREAT | O_TRUNC, 0644);

        while ((ent = readdir(dir)) != NULL) {
            if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0) {
                char path[512];
                sprintf(path, "%s/%s", dir_cale, ent->d_name);
                parsare_metadate(path, &metadate);
                dprintf(fptr, "%s\t%s\t%c\t%ld\t%s", metadate.nume, metadate.cale, metadate.tip, metadate.marime, ctime(&metadate.ultimaModificare));

                // Recursivitate pentru subdirectoare
                if (metadate.tip == 'D') {
                    char exe_path[512];
                    getcwd(exe_path, sizeof(exe_path));
                    strcat(exe_path, "/");
                    strcat(exe_path, argv[0]); // Modificarea aici
                    pid_t pid = fork();
                    if (pid == -1) {
                        perror("Eroare la crearea procesului copil");
                        exit(EXIT_FAILURE);
                    }
                    if (pid == 0) {
                        execl(exe_path, argv[0], "-o", argv[2], "-s", argv[4], path, NULL); // Modificarea aici
                        perror("Eroare în execl");
                        exit(EXIT_FAILURE);
                    }
                }
            }
        }
        close(fptr);
        closedir(dir);
    } else {
        perror("Eroare la deschiderea directorului");
        exit(EXIT_FAILURE);
    }
}

// Funcție pentru a analiza sintactic un fișier
void analizeaza_fisier(char *file_path, int *pipe_fd) {
    int fisier = open(file_path, O_RDONLY);
    if (fisier == -1) {
        perror("Eroare la deschiderea fișierului");
        exit(EXIT_FAILURE);
    }

    char ch;
    int linii = 0, cuvinte = 0, caractere = 0;
    int non_ASCII = 0;
    int cuvant_inceput = 0;

    // Analiza sintactică a fișierului
    while (read(fisier, &ch, 1) != 0) {
        caractere++;

        // Verifică caracterele non-ASCII
        if ((unsigned char)ch > 127) {
            non_ASCII = 1;
        }

        // Contorizează cuvintele
        if (ch == ' ' || ch == '\n' || ch == '\t') {
            if (cuvant_inceput) {
                cuvinte++;
                cuvant_inceput = 0;
            }
        } else {
            cuvant_inceput = 1;
        }

        // Contorizează liniile
        if (ch == '\n') {
            linii++;
        }
    }

    // Verifică dacă fișierul este corupt sau conține cuvinte cheie
    if ((linii < 3 && cuvinte > 1000 && caractere > 2000) || non_ASCII == 1) {
        // Scrie "CORUPT" prin pipe dacă fișierul este considerat corupt
        if (write(pipe_fd[1], "CORUPT", 7) == -1) {
            perror("Eroare la scrierea în pipe");
            exit(EXIT_FAILURE);
        }
        close(fisier);
        return;
    }

    // Verifică cuvintele cheie
    char *cuvinte_cheie[] = {"corrupted", "dangerous", "risk", "attack", "malware", "malicious"};
    char buffer[1024];
    lseek(fisier, 0, SEEK_SET);
    while (read(fisier, buffer, sizeof(buffer)) > 0) {
        for (int i = 0; i < sizeof(cuvinte_cheie) / sizeof(cuvinte_cheie[0]); i++) {
            if (strstr(buffer, cuvinte_cheie[i]) != NULL) {
                // Scrie "CORUPT" prin pipe dacă fișierul conține cuvinte cheie
                if (write(pipe_fd[1], "CORUPT", 7) == -1) {
                    perror("Eroare la scrierea în pipe");
                    exit(EXIT_FAILURE);
                }
                close(fisier);
                return;
            }
        }
    }

    if (write(pipe_fd[1], "SIGUR", 6) == -1) {
        perror("Eroare la scrierea în pipe");
        exit(EXIT_FAILURE);
    }

    close(fisier);
}

void izoleaza_fisier(char *cale_fisier, char *director_spatiu_izolat) {
    if (access(cale_fisier, F_OK) != 0) {
        printf("Fișierul %s nu există.\n", cale_fisier);
        return;
    }

    int pipe_fd[2];
    pid_t pid;
    char buffer[1024];

    if (pipe(pipe_fd) == -1) {
        perror("Eroare la crearea pipe-ului");
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid == -1) {
        perror("Eroare la crearea procesului copil");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) { // Proces copil
        close(pipe_fd[0]); // Închide capătul de citire al pipe-ului

        analizeaza_fisier(cale_fisier, pipe_fd);

        close(pipe_fd[1]); // Închide capătul de scriere al pipe-ului
        exit(EXIT_SUCCESS);
    } else { // Proces părinte
        close(pipe_fd[1]); // Închide capătul de scriere al pipe-ului

        int nbytes = read(pipe_fd[0], buffer, sizeof(buffer));
        if (nbytes == -1) {
            perror("Eroare la citirea din pipe");
            exit(EXIT_FAILURE);
        }
        buffer[nbytes] = '\0';

        if (strcmp(buffer, "CORUPT") == 0) {
            printf("Fișier corupt: %s\n", cale_fisier);
            char nume_fisier[256];
            sprintf(nume_fisier, "%s/%s", director_spatiu_izolat, strrchr(cale_fisier, '/') + 1);
            if (rename(cale_fisier, nume_fisier) == -1) {
                perror("Eroare la redenumirea fișierului");
                exit(EXIT_FAILURE);
            }
            printf("Fișierul \"%s\" a fost izolat cu succes.\n", cale_fisier);
        } else {
            printf("Fișier sigur: %s\n", cale_fisier);
        }

        close(pipe_fd[0]); // Închide capătul de citire al pipe-ului
    }
}

void compara_snapshoturi(char *snapshot_vechi_fisier, char *snapshot_nou_fisier, char *directorSpatiuIzolat, char *argv[]) {
    struct Metadata metadate_vechi, metadate_nou;
    char linie_veche[1024], linie_noua[1024];
    int f_vechi, f_nou;

    f_vechi = open(snapshot_vechi_fisier, O_RDONLY);
    f_nou = open(snapshot_nou_fisier, O_RDONLY);

    if (f_vechi == -1 || f_nou == -1) {
        perror("Eroare la deschiderea fișierelor de snapshot");
        exit(EXIT_FAILURE);
    }

    printf("Modificările:\n");

    // Parcurgere snapshot-ul nou
    while (read(f_nou, linie_noua, sizeof(linie_noua)) > 0) {
        int gasit = 0;
        char *token_nou = strtok(linie_noua, "\t");
        strcpy(metadate_nou.nume, token_nou);
        token_nou = strtok(NULL, "\t");
        strcpy(metadate_nou.cale, token_nou); // Se extrage calea completă a fișierului
        token_nou = strtok(NULL, "\t");
        metadate_nou.tip = token_nou[0];
        token_nou = strtok(NULL, "\t");
        metadate_nou.marime = atoi(token_nou);
        token_nou = strtok(NULL, "\t\n");
        metadate_nou.ultimaModificare = mktime(gmtime((const time_t *)&token_nou));

        // Parcurgere snapshot-ul vechi pentru a compara
        lseek(f_vechi, 0, SEEK_SET);
        while (read(f_vechi, linie_veche, sizeof(linie_veche)) > 0) {
            char *token_vechi = strtok(linie_veche, "\t");
            strcpy(metadate_vechi.nume, token_vechi);

            if (strcmp(metadate_nou.nume, metadate_vechi.nume) == 0) {
                gasit = 1;

                if (metadate_nou.ultimaModificare != metadate_vechi.ultimaModificare) {
                    printf("Fișier modificat: %s\n", metadate_nou.nume);
                }

                break;
            }
        }

        // Dacă fișierul/directorul nu a fost găsit în snapshot-ul vechi, este unul nou
        if (!gasit) {
            printf("Fișier nou: %s\n", metadate_nou.nume);
        }
    }

    // Parcurgere snapshot-ul vechi pentru a identifica fișierele/directoarele șterse
    lseek(f_vechi, 0, SEEK_SET);
    while (read(f_vechi, linie_veche, sizeof(linie_veche)) > 0) {
        int gasit = 0;
        char *token_vechi = strtok(linie_veche, "\t");
        strcpy(metadate_vechi.nume, token_vechi);
        token_vechi = strtok(NULL, "\t");
        strcpy(metadate_vechi.cale, token_vechi); // Se extrage calea completă a fișierului

        // Parcurgere snapshot-ul nou pentru a compara
        lseek(f_nou, 0, SEEK_SET);
        while (read(f_nou, linie_noua, sizeof(linie_noua)) > 0) {
            char *token_nou = strtok(linie_noua, "\t");
            strcpy(metadate_nou.nume, token_nou);

            if (strcmp(metadate_vechi.nume, metadate_nou.nume) == 0) {
                gasit = 1;
                break;
            }
        }

        // Dacă fișierul/directorul nu a fost găsit în snapshot-ul nou, a fost șters
        if (!gasit) {
            printf("Fișier șters: %s\n", metadate_vechi.nume);
            izoleaza_fisier(metadate_vechi.cale, directorSpatiuIzolat); // Se trimite calea completă a fișierului
        }
    }

    close(f_vechi);
    close(f_nou);
}

int main(int argc, char *argv[]) {
    if (argc < 6 || argc > 14 || strcmp(argv[1], "-o") != 0 || strcmp(argv[3], "-s") != 0) {
        printf("Opțiuni invalide. Utilizare: %s -o director_ieșire -s director_spațiu_izolare dir1 [dir2 dir3 ...]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char snapshot_vechi[512], snapshot_nou[512];
    sprintf(snapshot_vechi, "%s/Snapshot_vechi.txt", argv[2]);
    sprintf(snapshot_nou, "%s/Snapshot_nou.txt", argv[2]);

    // Compară snapshot-urile
    if (access(snapshot_vechi, F_OK) != -1) {
        compara_snapshoturi(snapshot_vechi, snapshot_nou, argv[4], argv);
    } else {
        printf("Aceasta este prima rulare, nu există snapshot vechi pentru comparație.\n");
    }

    // Creează snapshot nou
    creaza_snapshot(argv[5], snapshot_nou, argv[4], argv);

    return 0;
}
