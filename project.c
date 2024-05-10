#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>
#include <sys/wait.h>

struct Metadate {
    char nume[256];
    char cale[512];
    char tip;
    off_t dimensiune;
    time_t ultimaModificare;
};

void izoleazaFisier(char *caleFisier, char *directorCarantina) {
    if (access(caleFisier, F_OK) != 0) {
        printf("Fișierul %s nu există.\n", caleFisier);
        return;
    }

    printf("Izolarea fișierului: %s\n", caleFisier);

    int pipeFd[2];
    pid_t pid;
    char buffer[1024];

    if (pipe(pipeFd) == -1) {
        perror("Eroare la crearea pipe-ului");
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid == -1) {
        perror("Eroare la crearea procesului copil");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        close(pipeFd[0]);

        // Rulează scriptul pentru analiza fișierului
        char *args[] = {"./analizeaza_fisier.sh", caleFisier, NULL};
        dup2(pipeFd[1], STDOUT_FILENO); // Redirectează stdout către pipe
        execvp(args[0], args);

        // Dacă execvp() întoarce, înseamnă că a eșuat
        perror("Eroare la rularea scriptului de analiză a fișierului");
        exit(EXIT_FAILURE);
    } else {
        close(pipeFd[1]);

        int nbytes = read(pipeFd[0], buffer, sizeof(buffer));
        if (nbytes == -1) {
            perror("Eroare la citirea din pipe");
            exit(EXIT_FAILURE);
        }
        buffer[nbytes] = '\0';

        if (strcmp(buffer, "CORUPT\n") == 0) {
            printf("Fișier corupt: %s\n", caleFisier);
            char numeFisier[512];
            sprintf(numeFisier, "%s/%s", directorCarantina, strrchr(caleFisier, '/') + 1);
            if (rename(caleFisier, numeFisier) == -1) {
                perror("Eroare la redenumirea fișierului");
                exit(EXIT_FAILURE);
            }
            printf("Fișierul \"%s\" a fost izolat cu succes în \"%s\".\n", caleFisier, directorCarantina);
        } else if (strcmp(buffer, "SIGUR\n") == 0) {
            printf("Fișier sigur: %s\n", caleFisier);
        }

        close(pipeFd[0]);
    }
}

void parseazaMetadate(char *cale, struct Metadate *metadate) {
    struct stat fileStat;

    if (stat(cale, &fileStat) < 0)
        return;

    strcpy(metadate->nume, strrchr(cale, '/') + 1);
    strcpy(metadate->cale, cale);
    metadate->tip = (S_ISDIR(fileStat.st_mode)) ? 'D' : 'F';
    metadate->dimensiune = fileStat.st_size;
    metadate->ultimaModificare = fileStat.st_mtime;
}

void creazaSnapshot(char *caleDirector, char *fisierSnapshot, char *directorCarantina) {
    int filePtr;
    struct Metadate metadate;
    DIR *dir;
    struct dirent *entry;

    struct stat st = {0};
    if (stat(fisierSnapshot, &st) == -1) {
        mkdir(fisierSnapshot, 0777);
    }

    if ((dir = opendir(caleDirector)) != NULL) {
        char snapshotVechi[512], snapshotNou[512];
        sprintf(snapshotVechi, "%s/OldSnapshot.txt", fisierSnapshot);
        sprintf(snapshotNou, "%s/NewSnapshot.txt", fisierSnapshot);

        filePtr = open(snapshotNou, O_WRONLY | O_CREAT | O_TRUNC, 0644);

        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                char caleFisier[512];
                sprintf(caleFisier, "%s/%s", caleDirector, entry->d_name);
                parseazaMetadate(caleFisier, &metadate);
                dprintf(filePtr, "%s\t%s\t%c\t%ld\t%s", metadate.nume, metadate.cale, metadate.tip, metadate.dimensiune, ctime(&metadate.ultimaModificare));

                printf("Analizarea fișierului: %s\n", caleFisier);

                if (metadate.tip == 'F') {
                    izoleazaFisier(caleFisier, directorCarantina);
                }
            }
        }
        close(filePtr);
        closedir(dir);
    } else {
        perror("Eroare la deschiderea directorului");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 6 || argc > 14 || strcmp(argv[1], "-o") != 0 || strcmp(argv[3], "-s") != 0) {
        printf("Opțiuni invalide. Utilizare: %s -o director_output -s director_carantină dir1 [dir2 dir3 ...]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char snapshotVechi[512], snapshotNou[512];
    sprintf(snapshotVechi, "%s/OldSnapshot.txt", argv[2]);
    sprintf(snapshotNou, "%s/NewSnapshot.txt", argv[2]);

    if (access(snapshotVechi, F_OK) != -1) {
        // Compară snapshot-uri
        printf("Compararea snapshot-urilor:\n");
        // comparăSnapshoturi(snapshotVechi, snapshotNou, argv[4], argv);
    } else {
        printf("Aceasta este prima rulare, nu există vechiul snapshot pentru a compara.\n");
    }

    // Creează un nou snapshot
    printf("Crearea unui nou snapshot:\n");
    creazaSnapshot(argv[5], snapshotNou, argv[4]);

    return 0;
}
