# Medium — Italiano

**Titolo:** iCloudKit Extractor: sette mesi da un vicolo cieco ADP a un toolkit sperimentale pubblico  
**Sottotitolo:** Diario di ricerca Forensis-Lab — il progetto e le prime quattro giornate (marzo–maggio 2026)  
**Tag:** Informatica forense, iOS, iCloud, CloudKit, Open Source, Reverse Engineering  

---

## Perché esiste

A fine marzo 2026 avevamo un’esigenza forense concreta: scaricare un **backup iCloud di dispositivo** protetto da **Advanced Data Protection (ADP)**. I prodotti commerciali che usavamo, in quel momento, non ci davano quel percorso.

In laboratorio è un tipo di fallimento scomodo. Puoi rinnovare licenze, aprire ticket, attendere la release del vendor—oppure porre una domanda più dura: *cosa fanno davvero le superfici private Apple dietro la sezione iCloud di Impostazioni iOS?*

Sono **Giordano Sconti**, ricercatore software e consulente tecnico in collaborazione con **Forensis-Lab**. In circa sette mesi—spesso di notte o negli spiragli della giornata lavorativa—quella domanda è diventata **iCloudKit Extractor**: un toolkit sperimentale .NET / WPF per autenticazione iCloud, download backup via CloudKit / MMCS e percorsi Octagon / PCS quando si dispone già del PIN Octagon del dispositivo o della Recovery Key.

Il progetto è ora in **fase sperimentale pubblica** su GitHub con licenza **MIT**; proprietà e attribuzione restano di **Forensis-Lab**. È software di ricerca. Le API private di Apple possono cambiare da un giorno all’altro. Usatelo solo su account e dispositivi che siete autorizzati a esaminare.

- Repository: [github.com/GiordanoSconti/iCloudKitExtractor](https://github.com/GiordanoSconti/iCloudKitExtractor)  
- Note di ricerca: [Notes / blog su GitHub Pages](https://giordanosconti.github.io/iCloudKitExtractor/blog/)  
- Contatto: [giordano.sconti@gruppoinformaticiforensi.it](mailto:giordano.sconti@gruppoinformaticiforensi.it)

Le build Windows x64 sono pubblicate come Release GitHub firmate (Authenticode Forensis-Lab / Microsoft Trusted Signing). Per auditing forense preferite la build da sorgente.

---

## Cosa punta a fare il toolkit

In sintesi:

- **CloudKit / MMCS** — elencare dispositivi e scaricare payload di backup tramite autorizzazione CloudKit e flussi edge MMCS.  
- **Octagon / PCS** — percorsi Recovery Key e PIN verso i keyset Manatee / PCS per zone protette da ADP.  
- **Anisette** — backend opzionale Frida su iPhone jailbroken per un’identità iPhone / akd coerente in GrandSlam (l’accesso preview al server del maintainer è su invito).

L’obiettivo non era solo “avere un altro GUI”, ma rendere ispezionabile la *spina dorsale* del protocollo—così i recuperi estremi non dipendono soltanto dai buchi di copertura dei vendor.

---

## Giorno 1 — 25 marzo 2026: ADP sul tavolo

Le suite commerciali non bastavano. Con un collega abbiamo partito da due canali di osservazione pratici: un **iPhone jailbroken** e **Elcomsoft Phone Breaker** (avevo sia la licenza sia il device).

Le prime difficoltà gravitavano su **GrandSlam / GsService2**. EPB era rotto per i flussi che ci servivano; Elcomsoft corresse il mese dopo. Non aspettai: lavorai in parallelo su **iCloud.com** (token **idmsa**, utili al web, non ai client mobile nativi) e sul telefono jailbroken.

Quelle sessioni pagarono comunque: endpoint di autenticazione su **trusted devices** e **SMS**, e una visione più chiara dei metadati intorno ai media eliminati in **iCloud Photos**. Lato device comparvero GrandSlam mobile e i primi nomi CloudKit rilevanti per il backup—in particolare la zona **`mbksync`** nel container **`com.apple.backup.ios`** (backupd / Mobile Backup), non un generico “MobileSync”.

*Nel codice di oggi* quel binding è ancora esplicito:

```csharp
public static CloudKitContainerBinding Backup { get; } =
    new("com.apple.backup.ios", "com.apple.backupd");

public static readonly string[] BackupZones =
    { "_defaultZone", "mbksync" };
```

Nota completa: [Day 1](https://giordanosconti.github.io/iCloudKitExtractor/blog/posts/2026-03-25-day-01-adp-necessity.html)

---

## Giorno 2 — 11 aprile 2026: gli snapshot, ma non la montagna

Ripresi l’11 aprile. Arrivare agli endpoint di recupero snapshot fu duro in un altro modo: ogni tentativo sembrava riscrivere l’albero mentre l’agente di coding richiamava frammenti simili a materiale online.

Nel frattempo Elcomsoft pubblicò una build capace di scaricare backup **iOS 26**. Provai. Con **ADP** ancora attivo: **HTTP 403**. Usai quindi la loro release come oracolo di laboratorio su *come* avessero sbloccato almeno l’accesso agli snapshot. Le catture erano confuse; bastarono per superare l’**enumerazione degli snapshot**.

Non riuscivo ancora a decifrare **`backupProperties`**—dove vive l’**UDID** hardware. A malapena sapevo che il campo esistesse.

*Nel codice di oggi* quel campo è un percorso di decrypt di prima classe (ShareProtection → CUWK con label `backupProperties` → PCSFP-GCM), da cui emergono anche i dati Lockdown incluso UniqueDeviceID.

Nota completa: [Day 2](https://giordanosconti.github.io/iCloudKitExtractor/blog/posts/2026-04-11-day-02-snapshots-epb-403.html)

---

## Giorno 3 — 29 aprile 2026: Prepare Restore e il muro del Lock

Elencare gli snapshot non è preparare un restore. Su iOS vedi una fase di “preparazione”; sul cavo è una macchina a stati CloudKit che culmina in un **Lock** su `mbksync` prima che si apra il grande catalogo post-Lock (`N:`).

L’ordine che ancora documentiamo nell’extractor:

**zones → BackupAccount → `D:` → `S:` → (mbs opzionale) → Lock → `N:`**

Il Lock è una modify-records privata che scrive `{deviceSha}:Lock`. Se fallisce l’identità **Foreground Restore** hw/sha (o anche solo il wrapping sbagliato di un campo protobuf), MobileBackupServerExtension risponde **`Invalid lock id`**.

L’aiuto arrivò da una coalizione scomoda: **Frida** sull’iPhone jailbroken e alcune coppie richiesta/risposta **EPB malformate**—sbagliate per un download pulito, utili come fossili.

Nota completa: [Day 3](https://giordanosconti.github.io/iCloudKitExtractor/blog/posts/2026-04-29-day-03-prepare-restore-lock.html)

---

## Giorno 4 — 24 maggio 2026: si apre MMCS

Dopo un altro mese di reverse engineering oltre il Lock, misi piede in **MMCS**—host edge-content, GET a range, blob che rifiutano di essere una sola specie di byte. Lo stesso piano di range può portare **materiale chiavi Ford** o **ciphertext di chunk** dello stesso file logico. Se li classifichi male, i controlli MAC falliscono con fiducia perfetta.

A quel punto non mi servivano più telefono o EPB come stampella quotidiana per i *problemi successivi*. Gli agenti di coding—e frammenti pubblici più vecchi che puntavano a **Octagon**—aprirono strade che il percorso “restore normale” commerciale non pubblicizza. EPB restò rilevante come oracolo su **caching MMCS** e **riassemblaggio chunk**; anche così, per tutta l’estate entrambi lasciarono file indietro. Nei confronti, IKE teneva spesso dell’ordine di **~3000 file decifrati in più**.

Coda di settembre (anticipata nella nota di maggio): non ogni blob di chiavi Ford inizia con **`0x04`**; alcuni usano **`0xC4`**. Un nibble. Assurdo. Decisivo.

Nota completa: [Day 4](https://giordanosconti.github.io/iCloudKitExtractor/blog/posts/2026-05-24-day-04-mmcs-edge.html)

---

## Come seguire il lavoro

Continuerò a riempire il diario dei sette mesi nella pagina Notes del progetto. Le voci sono scritte con l’aiuto di un assistente AI di coding per velocizzare il racconto; se notate incongruenze, scrivetemi.

Chi vuole testare, revisionare o inviare pull request motivate è il benvenuto: rivedete sempre il codice generato, non introducete materiale di terzi senza licenza, e mantenete l’attribuzione a **Forensis-Lab**.

Se questo lavoro vi è utile, il segnale più utile non è un caffè: è il riconoscimento al laboratorio, test attenti e feedback tecnico.

---

*Giordano Sconti — Forensis-Lab*
