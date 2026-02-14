const questionsSource = [
    // --- LEVEL: BEGINNER (20 Soal) ---
    // Fokus: Dasar Subject-Verb Agreement (s/es) dan pola kalimat sederhana.

    {
        question: "She ______ to school every day.",
        options: ["go", "goes", "going", "gone"],
        answer: 1,
        explanation: "Subjek 'She' adalah orang ketiga tunggal (singular). Dalam Simple Present, kata kerja yang berakhiran 'o' (go) harus ditambah akhiran '-es'. Jadi 'goes'."
    },
    {
        question: "They ______ football in the park on Sundays.",
        options: ["plays", "play", "playing", "played"],
        answer: 1,
        explanation: "Subjek 'They' adalah jamak (plural). Kata kerja tidak mengalami perubahan (tetap bentuk dasar/V1). Jadi 'play'."
    },
    {
        question: "I ______ coffee every morning.",
        options: ["drink", "drinks", "drinking", "drank"],
        answer: 0,
        explanation: "Subjek 'I' menggunakan kata kerja bentuk dasar (V1) tanpa tambahan 's'. Jadi 'drink'."
    },
    {
        question: "He ______ very hard for his family.",
        options: ["work", "working", "works", "worked"],
        answer: 2,
        explanation: "Subjek 'He' (tunggal) memerlukan penambahan 's' pada kata kerja 'work'. Jadi 'works'."
    },
    {
        question: "The sun ______ in the east.",
        options: ["rise", "rises", "rising", "rose"],
        answer: 1,
        explanation: "Ini adalah fakta umum (general truth). Subjek 'The sun' adalah tunggal, maka kata kerja 'rise' ditambah 's'. Jadi 'rises'."
    },
    {
        question: "We ______ English twice a week.",
        options: ["study", "studies", "studying", "studied"],
        answer: 0,
        explanation: "Subjek 'We' (jamak) menggunakan kata kerja bentuk dasar. Jadi 'study'."
    },
    {
        question: "My mother ______ delicious cakes.",
        options: ["bake", "bakes", "baking", "baked"],
        answer: 1,
        explanation: "Subjek 'My mother' setara dengan 'She' (tunggal), maka kata kerja 'bake' ditambah 's'. Jadi 'bakes'."
    },
    {
        question: "______ you like chocolate?",
        options: ["Do", "Does", "Are", "Is"],
        answer: 0,
        explanation: "Untuk membuat kalimat tanya dengan subjek 'You', kita menggunakan auxiliary verb 'Do'."
    },
    {
        question: "The cat ______ milk.",
        options: ["like", "likes", "liking", "liked"],
        answer: 1,
        explanation: "Subjek 'The cat' (tunggal/it) memerlukan tambahan 's' pada kata kerja. Jadi 'likes'."
    },
    {
        question: "John and Mary ______ to the cinema every Friday.",
        options: ["goes", "go", "going", "gone"],
        answer: 1,
        explanation: "Subjek 'John and Mary' adalah jamak (mereka/they), jadi menggunakan kata kerja bentuk dasar 'go'."
    },
    {
        question: "______ she speak French?",
        options: ["Do", "Does", "Is", "Are"],
        answer: 1,
        explanation: "Subjek 'She' menggunakan auxiliary verb 'Does' dalam kalimat tanya."
    },
    {
        question: "It ______ a lot in winter here.",
        options: ["rain", "rains", "raining", "rained"],
        answer: 1,
        explanation: "Subjek 'It' (cuaca/keadaan) adalah tunggal, maka kata kerja 'rain' ditambah 's'. Jadi 'rains'."
    },
    {
        question: "You ______ beautiful today.",
        options: ["look", "looks", "looking", "looked"],
        answer: 0,
        explanation: "Subjek 'You' menggunakan kata kerja bentuk dasar 'look'."
    },
    {
        question: "My father ______ newspapers in the morning.",
        options: ["read", "reads", "reading", "reader"],
        answer: 1,
        explanation: "Subjek 'My father' (He) adalah tunggal, jadi kata kerja 'read' ditambah 's'. Jadi 'reads'."
    },
    {
        question: "Birds ______ in the sky.",
        options: ["fly", "flies", "flying", "flew"],
        answer: 0,
        explanation: "Subjek 'Birds' (jamak) menggunakan kata kerja bentuk dasar 'fly'."
    },
    {
        question: "The earth ______ around the sun.",
        options: ["go", "goes", "going", "gone"],
        answer: 1,
        explanation: "Fakta ilmiah. Subjek 'The earth' (tunggal) membutuhkan akhiran '-es' pada kata kerja 'go'."
    },
    {
        question: "I ______ to be a doctor.",
        options: ["want", "wants", "wanting", "wanted"],
        answer: 0,
        explanation: "Subjek 'I' menggunakan kata kerja bentuk dasar 'want' (tanpa s)."
    },
    {
        question: "Water ______ at 100 degrees Celsius.",
        options: ["boil", "boils", "boiling", "boiled"],
        answer: 1,
        explanation: "Fakta ilmiah. Subjek 'Water' (uncountable noun) dianggap tunggal, jadi 'boils'."
    },
    {
        question: "We ______ in a small house.",
        options: ["live", "lives", "living", "lived"],
        answer: 0,
        explanation: "Subjek 'We' menggunakan kata kerja bentuk dasar 'live'."
    },
    {
        question: "Tom ______ his teeth every night.",
        options: ["brush", "brushes", "brushing", "brushed"],
        answer: 1,
        explanation: "Subjek 'Tom' (He). Kata kerja berakhiran 'sh' (brush) harus ditambah '-es'. Jadi 'brushes'."
    },

    // --- LEVEL: INTERMEDIATE (20 Soal) ---
    // Fokus: Kalimat Negatif, Interrogative, Adverbs of Frequency, dan Pengecualian Ejaan.

    {
        question: "She ______ usually ______ breakfast.",
        options: ["doesn't / eat", "don't / eat", "doesn't / eats", "don't / eats"],
        answer: 0,
        explanation: "Kalimat negatif untuk 'She' menggunakan 'doesn't'. Setelah 'doesn't', kata kerja KEMBALI ke bentuk dasar (V1), jadi 'eat' (tanpa s)."
    },
    {
        question: "Where ______ you ______ ?",
        options: ["do / live", "does / live", "do / lives", "are / live"],
        answer: 0,
        explanation: "Pola pertanyaan Wh-question: Wh + do/does + Subject + V1. Subjek 'you' memakai 'do' dan 'live'."
    },
    {
        question: "He ______ always ______ the truth.",
        options: ["don't / tell", "doesn't / tell", "doesn't / tells", "isn't / tell"],
        answer: 1,
        explanation: "Subjek 'He' menggunakan 'doesn't' untuk negatif. Kata kerja utama 'tell' harus dalam bentuk dasar."
    },
    {
        question: "My brother ______ television very often.",
        options: ["watch", "watches", "watching", "is watch"],
        answer: 1,
        explanation: "Kata kerja berakhiran 'ch' (watch) dengan subjek tunggal 'My brother' harus ditambah '-es'. Jadi 'watches'."
    },
    {
        question: "______ your parents ______ coffee?",
        options: ["Do / drink", "Does / drink", "Do / drinks", "Does / drinks"],
        answer: 0,
        explanation: "Subjek 'Your parents' adalah jamak (They), jadi menggunakan auxiliary 'Do'. Kata kerja utama 'drink' tetap V1."
    },
    {
        question: "I ______ agree with your opinion.",
        options: ["doesn't", "not", "am not", "don't"],
        answer: 3,
        explanation: "Untuk membuat kalimat negatif dengan kata kerja 'agree' dan subjek 'I', gunakan 'don't'."
    },
    {
        question: "The baby ______ whenever he is hungry.",
        options: ["cry", "crys", "cries", "crying"],
        answer: 2,
        explanation: "Aturan ejaan: Kata kerja berakhiran konsonan + y (cry), ubah 'y' menjadi 'i' lalu tambah 'es'. Jadi 'cries'."
    },
    {
        question: "We ______ often ______ to the library.",
        options: ["doesn't / go", "don't / go", "don't / goes", "not / go"],
        answer: 1,
        explanation: "Subjek 'We' menggunakan 'don't' untuk bentuk negatif. Kata kerja 'go' kembali ke bentuk dasar."
    },
    {
        question: "What time ______ the shop ______ ?",
        options: ["do / close", "does / closes", "does / close", "is / close"],
        answer: 2,
        explanation: "Subjek 'the shop' (It) tunggal, jadi pakai auxiliary 'does'. Kata kerja utama 'close' harus V1 (tanpa s)."
    },
    {
        question: "She ______ English, but she ______ Mandarin.",
        options: ["study / doesn't study", "studies / don't study", "studies / doesn't study", "study / don't studies"],
        answer: 2,
        explanation: "Kalimat positif: 'studies' (She + V1+es). Kalimat negatif: 'doesn't study' (She + doesn't + V1)."
    },
    {
        question: "______ John play the guitar?",
        options: ["Do", "Does", "Is", "Are"],
        answer: 1,
        explanation: "Subjek 'John' (He) menggunakan auxiliary 'Does' dalam kalimat tanya."
    },
    {
        question: "They never ______ their homework on time.",
        options: ["finish", "finishes", "finishing", "finished"],
        answer: 0,
        explanation: "Adverb 'never' tidak mengubah aturan gramatikal dasar. Subjek 'They' tetap menggunakan V1 'finish'."
    },
    {
        question: "How often ______ she ______ her grandmother?",
        options: ["do / visit", "does / visit", "does / visits", "is / visit"],
        answer: 1,
        explanation: "Pertanyaan frekuensi. Subjek 'she' memakai 'does', dan kata kerja utama 'visit' harus V1."
    },
    {
        question: "Mr. Smith ______ mechanics at the university.",
        options: ["teach", "teaches", "teaching", "teacher"],
        answer: 1,
        explanation: "Kata kerja berakhiran 'ch' (teach) ditambah 'es' untuk subjek tunggal 'Mr. Smith'. Jadi 'teaches'."
    },
    {
        question: "I ______ know the answer.",
        options: ["doesn't", "not", "am not", "don't"],
        answer: 3,
        explanation: "Kalimat negatif verbal untuk 'I' menggunakan 'don't'."
    },
    {
        question: "Our class ______ at 8 AM.",
        options: ["start", "starts", "starting", "is start"],
        answer: 1,
        explanation: "Subjek 'Our class' (It) adalah tunggal. Kata kerja 'start' ditambah 's'."
    },
    {
        question: "Why ______ you always ______ late?",
        options: ["do / come", "does / come", "are / come", "do / comes"],
        answer: 0,
        explanation: "Subjek 'you' menggunakan 'do'. Kata kerja 'come' tetap V1."
    },
    {
        question: "The bus ______ not stop here.",
        options: ["do", "does", "is", "are"],
        answer: 1,
        explanation: "Subjek 'The bus' (tunggal) menggunakan 'does' dalam bentuk negatif (does not)."
    },
    {
        question: "______ it rain much in the desert?",
        options: ["Do", "Does", "Is", "Are"],
        answer: 1,
        explanation: "Subjek 'it' menggunakan auxiliary 'Does' untuk bertanya."
    },
    {
        question: "My sister ______ her room every Saturday.",
        options: ["tidy", "tidies", "tidys", "tidying"],
        answer: 1,
        explanation: "Aturan ejaan: 'tidy' (berakhiran konsonan+y) berubah menjadi 'tidies' (y -> i + es) untuk subjek tunggal."
    },

    // --- LEVEL: EXPERT (10 Soal) ---
    // Fokus: Stative Verbs, Future Timetables, dan Struktur Kompleks.

    {
        question: "The train for London ______ at 9:00 PM tonight.",
        options: ["leave", "leaves", "is leaving", "will leave"],
        answer: 1,
        explanation: "Jadwal/Timetable: Simple Present digunakan untuk menyatakan kejadian di masa depan yang sudah terjadwal (seperti jadwal kereta/pesawat). 'Leaves' adalah jawaban paling tepat secara grammar untuk jadwal."
    },
    {
        question: "I ______ what you mean.",
        options: ["understand", "understands", "am understanding", "understanding"],
        answer: 0,
        explanation: "Stative Verb: Kata kerja 'understand' berkaitan dengan pikiran/kognisi dan umumnya TIDAK digunakan dalam bentuk continuous (ing). Jadi 'understand'."
    },
    {
        question: "This soup ______ delicious.",
        options: ["taste", "tastes", "is tasting", "tasting"],
        answer: 1,
        explanation: "Stative Verb: Ketika 'taste' berarti 'memiliki rasa', itu adalah stative verb. Subjek 'This soup' tunggal, jadi 'tastes'."
    },
    {
        question: "Unless he ______, he will miss the bus.",
        options: ["hurry", "hurries", "will hurry", "hurrying"],
        answer: 1,
        explanation: "Conditional Sentence Type 1: Pada 'if clause' atau 'unless clause', kita menggunakan Simple Present untuk merujuk ke masa depan. Subjek 'he' -> 'hurries'."
    },
    {
        question: "Everything ______ fine.",
        options: ["seem", "seems", "is seeming", "seeming"],
        answer: 1,
        explanation: "Indefinite Pronoun 'Everything' selalu dianggap tunggal. 'Seem' adalah stative verb, jadi ditambah 's' menjadi 'seems'."
    },
    {
        question: "What ______ 'procrastinate' ______ ?",
        options: ["do / mean", "does / mean", "is / meaning", "does / means"],
        answer: 1,
        explanation: "Subjek kalimat ini adalah kata 'procrastinate' (It/kata itu), jadi menggunakan auxiliary 'does'. Kata kerja 'mean' (stative) kembali ke V1."
    },
    {
        question: "Nobody ______ the trouble I've seen.",
        options: ["know", "knows", "knowing", "is know"],
        answer: 1,
        explanation: "Indefinite Pronoun 'Nobody' secara gramatikal dianggap tunggal (singular). Maka kata kerja 'know' ditambah 's' menjadi 'knows'."
    },
    {
        question: "She ______ everything involves money.",
        options: ["think", "thinks", "is thinking", "thinking"],
        answer: 1,
        explanation: "Stative Verb: Ketika 'think' berarti 'berpendapat' (opinion), kita menggunakan Simple Present, bukan Continuous. Subjek 'She' -> 'thinks'."
    },
    {
        question: "Here ______ the bus!",
        options: ["come", "comes", "is coming", "coming"],
        answer: 1,
        explanation: "Exclamatory Sentence: Dalam kalimat seru yang dimulai dengan 'Here' atau 'There', kita menggunakan Simple Present. Karena 'the bus' tunggal, jadinya 'comes'."
    },
    {
        question: "Either my father or my brothers ______ coming to the meeting.",
        options: ["is", "are", "do", "does"],
        answer: 1,
        explanation: "Subject-Verb Agreement dengan 'Either...or...': Kata kerja mengikuti subjek yang paling DEKAT dengannya. Subjek terdekat adalah 'my brothers' (jamak), jadi menggunakan 'are'."
    }
];