#include <stdio.h>

#if defined(_WIN32)
#include <Windows.h>
#endif

#include <string.h>
#include <stdlib.h>


static const char *default_translate_data[] = {
	"************** WARNING: NOT Running as Admin/Root **************@************** AVERTISSEMENT: ne fonctionne pas en tant qu'administrateur / racine **************",
	"Active@Actif",
	"Allocation Failed@�chec de l'allocation",
	"automatically attempt to register sightings with MISP server@tenter automatiquement d'enregistrer les observations aupr�s du serveur MISP",
	"Begin Module Import@Commencer l�importation du module",
	"bit flags for basic (0), meta (1), string matches (2), tags (4)@Octet d�indication pour basic (0), meta (1), correspondances de cha�nes (2), tags (4)",
	"Checking IP@V�rification IP",
	"CMD Hit@CMD indicateur",
	"Compiled rules file corrupt@Fichier compil� corrompu",
	"Completed Upload of Detected Samples@T�l�chargement des �chantillons d�tect�s termin�s",
	"Could not allocate scan results data@Impossible d'allouer les donn�es de r�sultats de l�analyse",
	"Could not attach to process@Impossible de joindre au processus",
	"Could not create thread!@Impossible de cr�er la s�quence!",
	"Could not define external variable is_filescan to@Impossible de d�finir la variable externe is_filescan sur",
	"Could not initialize curl for signature file download@Impossible d'initialiser la boucle pour le t�l�chargement du fichier de signature",
	"Could not initialize curl for upload of file@Impossible d'initialiser la boucle pour le t�l�chargement du fichier",
	"Could not initialize curl for upload of hit result@Impossible d'initialiser la boucle pour le t�l�chargement du r�sultat de hit",
	"Could not initialize curl for upload of results file@Impossible d'initialiser la boucle pour le t�l�chargement du fichier de r�sultats",
	"Could not open file@Impossible d'ouvrir le fichier",
	"Could not open signature file for download.@Impossible d'ouvrir le fichier de signature � t�l�charger.",
	"CPU throttling number of MICROSECONDS to sleep between file scans@La limitation du processeur en MICROSECONDS pour dormir entre les analyses de fichiers",
	"Detail File Hit@D�tail du fichier atteint",
	"Detected Files Warning@Avertissement des fichiers d�tect�s",
	"Development Signatures Mode Active@Mode de signature de d�veloppement Active",
	"Directories Skipped@R�pertoires ignor�s",
	"Directory Access Denied@Acc�s � l'annuaire refus�",
	"DirList Values@Valeurs DirList",
	"dirlist.txt data ignored@donn�es dirlist.txt ignor�es",
	"display the tool and yara version and exit@afficher l'outil, la version yara et quitter",
	"DNS Buffer@Tampon DNS",
	"DNS Buffered@Tampon DNS",
	"DNS Hit@DNS Hit",
	"DNS List Interrupted@Liste DNS interrompue",
	"DNS Scan@DNS Scan",
	"DNS Signature Items Loaded@Les signatures DNS sont charg�s",
	"Download error occurred for signature file@Une erreur de t�l�chargement s'est produite pour le fichier de signature",
	"download new set of rules and signatures then exit@T�l�chargez un nouvel ensemble de r�gles et de signatures puis quittez",
	"Downloading rules and signature files@T�l�chargement des r�gles et les fichiers de signatures",
	"End@Fin",
	"Endpoint Scanner Version@Version de l�outils EPST",
	"Environment Variables@Variables du syst�me",
	"EOF Not Reached@EOF non atteint",
	"EPST File Scan@V�rifications compl�t� par l�EPST",
	"Error: dirlist memory allocation failed!@Erreur: l'allocation de la m�moire pour la liste de lecture a �chou�!",
	"Event Details Exceeded Buffer@La m�moire tampon est pleine",
	"Event Hits Warning@Avertissement d�activit�s suspecte",
	"Event ID Found Stats@Activit�s d�identification statistique",
	"Event ID Signature Items Loaded@Activit�s d�identification d�activit�s charg�s",
	"Event Log Buffer@Activit�s tampon du journal des activit�s",
	"Event Log Enumerate List Interrupted@Journal des activit�s interrompue",
	"Event Log Enumerate List@Journal des activit�s",
	"Event Log Query Interrupted@Requ�te du journal des activit�s interrompue",
	"Event Log Query Parse@Analyser la requ�te du journal des activit�s",
	"Event Log Scan@Analyse du journal des activit�s",
	"Event Scan@Analyse des activit�s",
	"Event Signature Alloc Failed@L'allocation de signature d'activit�s a �chou�",
	"EVT Hit@EVT Hit",
	"Excluded@Exclu",
	"Executable folder not added to exclude directory list!@Dossier ex�cutable non ajout� pour exclure la liste des r�pertoires!",
	"Existing file could not be renamed as a backup.@Le fichier existant n'a pas pu �tre renomm� en tant que sauvegarde.",
	"ExpandEnvironmentStrings error occurred@Une erreur ExpandEnvironmentStrings s'est produite",
	"ExpandEnvironmentStrings exceeded buffer size!@ExpandEnvironmentStrings a d�pass� la taille de la m�moire tampon!",
	"Experimental Development Signatures Mode Active@Mode de signature experimental est actif",
	"Experimental Mode Active@Mode exp�rimental actif",
	"Experimental Signatures Mode Active@Mode de signatures exp�rimentales actif",
	"Failed@�chou�",
	"FALSE@FAUX",
	"fast matching mode@mode de correspondance rapide",
	"File could not be removed.@Le fichier n'a pas pu �tre supprim�.",
	"File Data Buffer@Ficher en memoire tampon",
	"File does not exist for upload@Le fichier n'existe pas pour le t�l�chargement en amont",
	"File Scan Complete@Analyse de fichiers termin�e",
	"File Scan@Analyse de fichiers",
	"Filename Signature Items Loaded@�l�ments de signature de nom de fichier charg�s",
	"Filenames Scan@Filenames Scan",
	"Filepath strdup error@Erreur de chemin du fichier strdup",
	"Files Skipped@Fichiers ignor�s",
	"Finalizing Threads@Finalisation des s�quences",
	"Finished Endpoint Scan@Analyse compl�t� par l�outil EPST",
	"Finished File Scan@Analyse de fichiers termin�e",
	"Finished Process Scan@Analyse de processus termin�e",
	"Finished System Scan@Analyse syst�me termin�e",
	"Finished@Fini",
	"force scanning to complete after max number of SECONDS@L�analyse forc�e compl�t� apr�s SECONDS maximum",
	"Found Out of Range Event ID:@L�activit� d�identification est hors de port�e",
	"Get Process IDs@Obtenir les identifications",
	"Hash could not be calculated for results file@Le hachage n'a pas pu �tre calcul� pour le fichier de r�sultats",
	"hash files and check master MD5, SHA1, SHA256 hit lists@Le hachage des fichiers et la validation des listes de r�sultats principales MD5, SHA1, SHA256",
	"Hash scan could not allocate file data@L�outil de hachage n'a pas pu allouer les donn�es de fichier",
	"Hash scan could not read file@Loutil de hachage n'a pas pu lire le fichier",
	"Hash Scan@L�outil de hachage",
	"HIT@Hit",
	"Important Files (Rules, Signatures, Trace, Results):@Fichiers importants (r�gles, signatures, trace, r�sultats):",
	"Internal Error@Erreur interne",
	"Invalid arguments for hash function (md5, sha1, sha256 or checksum32)@Arguments non valides pour la fonction de hachage (md5, sha1, sha256 ou checksum32)",
	"Invalid external variable type@Type de variable externe non valide",
	"IP Address Scan@Scan d'adresse IP",
	"IP Hit@IP Hit",
	"IP Signature Items Loaded@�l�ments de signature IP charg�s",
	"level of extra details in the trace (0,1,2,3)@niveau de d�tails suppl�mentaires dans la compilation (0,1,2,3)",
	"Loading compiled Yara rule file@Chargement du fichier des r�gles Yara est compil�",
	"Maximum number of threads is@Le nombre maximum de threads est",
	"MD5 Signature Items Loaded@�l�ments de signature MD5 charg�s",
	"MUTANT Hit@MUTANT Hit",
	"Mutex Scan@Mutex Scan",
	"Mutex Signature Items Loaded@Articles de signature Mutex charg�s",
	"No API Key available for scan results upload.@Aucune cl� API disponible pour le t�l�chargement des r�sultats de l'analyse.",
	"No API Key available for trace file upload.@Aucune cl� API disponible pour le t�l�chargement du fichier de trace.",
	"No API Key available for upload.@Aucune cl� API disponible pour le t�l�chargement.",
	"No Log Files Found@Aucun fichier journal trouv�",
	"None Found@Rien trouv�",
	"Not Active@Pas actif",
	"Not Allocated@Pas allou�",
	"Not Running as Admin: Skipping Event Log Scan@Compte administrateur non s�lectionn�: ignorer l'analyse du journal des �v�nements",
	"Not Running as Admin: Skipping Process Scan@Compte administrateur non s�lectionn�: ignorer l'analyse de processus",
	"NOT Running as User Admin@Compte administrateur non s�lectionn�",
	"number of SECONDS before a file or process scan times out@Nombre de SECONDS requis avant l'expiration d'un fichier ou d'un processus",
	"Old backup could not be removed.@Sauvegarde d�archive n�a pas pu �tre supprim�e.",
	"Old version of file could not be removed.@L'ancienne version du fichier n'a pas pu �tre supprim�e.",
	"Open DNS List@Ouvrir la liste DNS",
	"Open Failed@�chec d'ouverture",
	"Open Socket List@Ouvrir la liste des sockets",
	"Out of memory@M�moire insuffisante",
	"Output Data@Des donn�es de sortie(output)",
	"Output Search Signatures@Signatures de recherche de sortie(output)",
	"per file max NUMBER of matching rules to record@NOMBRE maximum de r�gles correspondantes pour un ficher",
	"PID@PID",
	"Pipe Open Failed@�chec d�ouverture",
	"Please manually restore from backup or try again later.@Veuillez restaurer manuellement � partir de la sauvegarde ou r�essayer plus tard.",
	"Process Identification Interrupted@Activit� Identification interrompue",
	"Process IDs Found@Activit� Identification trouv�e",
	"Process IDs@Activit� Identification",
	"Process List@Liste des activit�s",
	"Process Memory Scan@Activit� d�analyse de la m�moire vive",
	"Processing@En traitement",
	"Query Enumerate Event Logs@�num�ration de la liste d��venements ",
	"Read File Data Size Difference@Lire la diff�rence de taille des donn�es de fichier",
	"Read File Data Warning@Lire les donn�es de l'avertissement",
	"Read File Header Warning@Lire l'en-t�te de l'avertissement de fichier",
	"Register Keys Signature Items Loaded@Enregistrer les �l�ments de signature des cl�s charg�s",
	"Registry Hit@Activit� trouv� dans le registre",
	"Registry Keys Scan@Analyse des cl�s de registre",
	"Registry Scan@Analyse du registre",
	"regrun environment variable is@la variable d'environnement regrun est",
	"Results file does not exist for upload@Le fichier de r�sultats n'existe pas pour le t�l�chargement",
	"Results File Hash@Fichier de r�sultats Hash",
	"Results File@Fichier de r�sultats",
	"Rules compiled with wrong version@R�gles compil�es avec une mauvaise version",
	"Running as User Admin@Ex�cution en tant qu'administrateur utilisateur",
	"scan active sockets and dns cache for IPs in hit list@analyser les sockets actifs et le cache DNS pour les IP dans la liste de r�sultats",
	"scan directory tree for file names in hit list@analyser l'arborescence des r�pertoires pour les noms de fichiers dans la liste de r�sultats",
	"Scan Event Log@Journal des activit�s",
	"scan event logs and command output for specific events@Analyser les journaux d'activit�s et les sorties de commande pour des activit�s sp�cifiques",
	"Scan Event Logs@Analyser les journaux d'activit�s",
	"Scan file upload failed@�chec du t�l�chargement du fichier d'analyse",
	"scan files with yara rules@analyser les fichiers avec les r�gles yara",
	"Scan hit value upload failed@Le t�l�chargement de la valeur de hit a �chou�",
	"scan memory of all active processes with Yara rules@analyser la m�moire de tous les processus actifs avec les r�gles Yara",
	"scan mutex items for keys in hit list@analyser les �l�ments mutex pour rechercher les cl�s dans la liste de r�sultats",
	"Scan report upload failed@�chec du t�l�chargement du rapport d'analyse",
	"scan the URL cache for items in the hit list@analysez le cache URL pour les �l�ments de la liste de r�sultats",
	"scan the DNS cache for items in the hit list@analysez le cache DNS pour les �l�ments de la liste de r�sultats",
	"scan the registry for keys in hit list@rechercher dans le registre les cl�s de la liste de r�sultats",
	"Scanned Directory@Balayage du r�pertoire",
	"Scanned@Le balayage",
	"Scanning timed out@Le balayage a expir�",
	"set maximum stack size (default=16384)@d�finir la taille maximale de la pile (par d�faut = 16384)",
	"SHA1 Signature Items Loaded@�l�ments de signature SHA1 charg�s",
	"SHA256 Signature Items Loaded@�l�ments de signature SHA256 charg�s ",
	"show this help and exit@afficher l�aide et quitter",
	"Sighting@Observation",
	"Signature List Read Realloc Failed - continuing@�chec de la r�-allocation de la liste de signatures - continuer",
	"Skipping Directory@Ignorer le r�pertoire",
	"Skipping Path Too Long@Ignorer ficher trop long",
	"Skipping Symbolic Link@Ignorez le lien symbolique",
	"Skipping Yara Rules File@Ignorez le fichier de r�gles Yara",
	"Socket Identification Interrupted@Socket Identification interrompu",
	"Socket Scan@Socket Scan",
	"specify folder name for downloaded and generated files@sp�cifiez le nom du dossier pour les fichiers t�l�charg�s et g�n�r�s",
	"specify name for a compiled Yara rules file@sp�cifiez le nom d'un fichier de r�gles Yara compil�",
	"specify NUMBER of threads to use for scanning files@sp�cifier le NOMBRE de threads � utiliser pour analyser les fichiers",
	"Stack overflow evaluating condition@Stack overflow evaluation des conditions",
	"Start@D�but",
	"Started@Commenc�",
	"Starting Endpoint Scan@D�marrage de l�outil EPST",
	"Starting System Scan@D�marrage du system de balayage",
	"suppress default upload of hit samples to MISP server@supprimer le t�l�chargement par d�faut des �chantillons de r�sultats sur le serveur MISP",
	"suppress default upload of results to MISP server@supprimer le t�l�chargement par d�faut des r�sultats sur le serveur MISP",
	"SysCmds Scan@SysCmds Balayage",
	"System Command Items Loaded@Commandes du syst�me charg�s",
	"System Command Not Executed@Commandes du syst�me non ex�cut�e",
	"System Command Signature Items Loaded@Commandes du syst�me: �l�ments de signature charg�s",
	"System Command Start@Commandes du syst�me pour commencer",
	"System Command@Commandes du syst�me",
	"System Commands to Run@Commandes du syst�me pour ex�cuter",
	"System Config Interrupted@System Config Interrupted",
	"System Config@System Config",
	"Terminating Program@Conclusion du programme",
	"Thread@Thread",
	"Threaded Processing@En traitement",
	"Threading Queue Initialization Failed!@�chec de l'initialisation de la file d'attente!",
	"Timed Out@Fin du temps allou�",
	"Timed Out@Fin du temps allou�",
	"End Point Scanning Tool uses signature data and Yara rules@L'outil d'analyse de point final utilise les donn�es de signature et les r�gles Yara",
	"to check files, processes and system resources for malware.@pour v�rifier les fichiers, les processus et les ressources syst�me pour les logiciels malveillants.",
	"Trace File Warning@Avertissement de fichier de trace",
	"trace to file (1), trace to stdout (2) both (3)@Trace vers le fichier (1), trace vers stdout (2) both (3)",
	"TRUE@VRAI",
	"Truncating@Truncating",
	"turn on explicit scan mode so all are off by default@Activer le mode d�analyse explicite pour que tous soient d�sactiv�s par d�faut",
	"Unknown Hive Name for registry key@Nom de fich� m�re inconnu pour la cl� de registre",
	"Upload Detected Files Read Warning@T�l�charger les fichiers d�tect�s, lire l'avertissement",
	"upload existing results file then exit@T�l�charger le fichier de r�sultats existant puis quitter",
	"Uploading Detected Samples@T�l�chargement en amont d'�chantillons d�tect�s",
	"Uploading results JSON file.@T�l�chargement du fichier JSON des r�sultats.",
	"Uploading results JSON file@T�l�chargement des r�sultats du fichier JSON",
	"Uploading results trace file.@T�l�chargement du fichier de suivi des r�sultats.",
	"URL failed@L'URL a �chou�",
	"use development vs normal yara rules@utiliser le d�veloppement vs les r�gles normales de yara",
	"use experimental vs normal yara rules (same filename, different download)@Utilisation de r�gles yara exp�rimentales vs normales (m�me nom de fichier, t�l�chargement diff�rent)",
	"use local rules and signature files already downloaded@Utiliser les r�gles locales et les fichiers de signatures d�j� t�l�charg�s",
	"Using Packaged Cert@Utilisation de Packaged Cert",
	"Validated Event Signatures@Signatures d'activit�s valid�es",
	"Validated Regex Signatures@Signatures Regex valid�es",
	"WARNING: Another EPST may be running. Skipping@AVERTISSEMENT: EPST est pr�sentement ouvert dans un autre fen�tre. Ignorer",
	"WARNING: Check Expanded DirList Item@AVERTISSEMENT: V�rifiez l'�l�ment DirList",
	"Warning: Could not read header for EPST Rules File Check@AVERTISSEMENT: Impossible de lire l'en-t�te pour la v�rification du fichier de r�gles EPST",
	"WARNING: DNS Regex Search Result Out of Bounds@AVERTISSEMENT: R�sultat de recherche DNS Regex hors limites",
	"Warning: Header Mismatch for EPST Rules File Check@AVERTISSEMENT: incompatibilit� avec l�outil EPST",
	"Yara Development Mode Active@Mode de d�veloppement Yara Actif",
	"Yara Initialization Code@Code d�initialization Yara",
	"YARA Library Version@Version de YARA",
	"Yara rule file is invalid or not compiled@Le fichier des r�gles Yara n'est pas valide ou n'est pas compil�",
	"Yara Rule Scanning@Analyse des r�gles Yara",
	NULL
};

int split_add_translate_data_line(char *line);

int use_default_translate_data() {
	int i = 0;
	const char *s;
	char buf[2048 + 1];

	while ((s = default_translate_data[i]) != NULL) {
		// Copy const string into buffer for the split
		strncpy(buf, s, 2048);
		buf[2048] = '\0';
		split_add_translate_data_line(buf);
		i++;
	}

	return i;
}