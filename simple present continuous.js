const questionsSource = [
    // --- LEVEL: BEGINNER (20 Soal) ---
    // Fokus: Rumus dasar, To Be (Am/Is/Are), dan V-ing dasar.

    {
        question: "I ______ watching TV right now.",
        options: ["is", "am", "are", "be"],
        answer: 1,
        explanation: "Subjek 'I' selalu berpasangan dengan to be 'am' dalam Present Continuous Tense."
    },
    {
        question: "She ______ a book at the moment.",
        options: ["reading", "is reading", "are reading", "read"],
        answer: 1,
        explanation: "Subjek tunggal (She) menggunakan to be 'is' diikuti Verb-ing. Jadi: 'is reading'."
    },
    {
        question: "They ______ football in the park.",
        options: ["is playing", "am playing", "are playing", "plays"],
        answer: 2,
        explanation: "Subjek jamak (They) menggunakan to be 'are' diikuti Verb-ing. Jadi: 'are playing'."
    },
    {
        question: "______ you listening to me?",
        options: ["Is", "Am", "Are", "Do"],
        answer: 2,
        explanation: "Kalimat tanya dengan subjek 'You' menggunakan to be 'Are' di awal kalimat."
    },
    {
        question: "Look! The bus ______.",
        options: ["come", "coming", "is coming", "are coming"],
        answer: 2,
        explanation: "Kata 'Look!' adalah penanda kejadian sedang berlangsung. Subjek 'The bus' (tunggal) menggunakan 'is coming'."
    },
    {
        question: "We ______ not studying right now.",
        options: ["is", "am", "are", "do"],
        answer: 2,
        explanation: "Subjek 'We' menggunakan to be 'are'. Untuk negatif ditambahkan 'not' (sudah ada di soal)."
    },
    {
        question: "My mother is ______ dinner in the kitchen.",
        options: ["cook", "cooks", "cooking", "cooked"],
        answer: 2,
        explanation: "Setelah to be (is), kata kerja harus dalam bentuk -ing (Present Participle) untuk membentuk Continuous Tense."
    },
    {
        question: "The cat ______ sleeping on the sofa.",
        options: ["is", "are", "am", "be"],
        answer: 0,
        explanation: "Subjek 'The cat' (singular/he/she/it) menggunakan to be 'is'."
    },
    {
        question: "John and Sarah ______ doing their homework.",
        options: ["is", "am", "are", "was"],
        answer: 2,
        explanation: "Subjek gabungan 'John and Sarah' adalah jamak (mereka/they), jadi menggunakan 'are'."
    },
    {
        question: "Please be quiet. The baby ______.",
        options: ["sleeps", "is sleeping", "are sleeping", "slept"],
        answer: 1,
        explanation: "Konteks 'Please be quiet' menunjukkan aksi sedang berlangsung sekarang. Subjek tunggal menggunakan 'is sleeping'."
    },
    {
        question: "I am ______ a letter to my friend.",
        options: ["write", "writing", "writting", "writes"],
        answer: 1,
        explanation: "Aturan ejaan: Kata kerja berakhiran 'e' (write) membuang huruf 'e' sebelum ditambah -ing. 'Writing' (satu t)."
    },
    {
        question: "He ______ sitting on the chair.",
        options: ["is", "are", "am", "do"],
        answer: 0,
        explanation: "Subjek 'He' menggunakan to be 'is'."
    },
    {
        question: "______ she working today?",
        options: ["Is", "Are", "Do", "Does"],
        answer: 0,
        explanation: "Pertanyaan Present Continuous dengan subjek 'She' dimulai dengan 'Is'."
    },
    {
        question: "They are ______ very fast.",
        options: ["run", "runing", "running", "runs"],
        answer: 2,
        explanation: "Aturan ejaan: Kata satu suku kata berakhiran Konsonan-Vokal-Konsonan (run) menggandakan huruf terakhir. Jadi 'running'."
    },
    {
        question: "It is ______ heavily outside.",
        options: ["rain", "raining", "rains", "rained"],
        answer: 1,
        explanation: "Setelah 'is', gunakan V-ing: 'raining'."
    },
    {
        question: "We are ______ a good time.",
        options: ["have", "having", "has", "had"],
        answer: 1,
        explanation: "Ejaan: 'Have' berakhiran 'e', buang 'e' lalu tambah -ing menjadi 'having'."
    },
    {
        question: "Where ______ you going?",
        options: ["is", "am", "are", "do"],
        answer: 2,
        explanation: "Pertanyaan Wh-question dengan subjek 'you' menggunakan auxiliary 'are'."
    },
    {
        question: "The birds ______ singing beautifully.",
        options: ["is", "are", "am", "was"],
        answer: 1,
        explanation: "Subjek 'The birds' (jamak) menggunakan 'are'."
    },
    {
        question: "I am not ______ my phone.",
        options: ["use", "using", "uses", "used"],
        answer: 1,
        explanation: "Bentuk negatif 'am not' tetap diikuti oleh V-ing ('using')."
    },
    {
        question: "Look at the man. He ______ .",
        options: ["dance", "is dancing", "are dancing", "dances"],
        answer: 1,
        explanation: "Kejadian terjadi saat dilihat (Look). Subjek tunggal 'He' memakai 'is dancing'."
    },

    // --- LEVEL: INTERMEDIATE (20 Soal) ---
    // Fokus: Future arrangement, Temporary situation, Negatives, & Spelling rules lanjutan.

    {
        question: "I ______ my dentist tomorrow morning.",
        options: ["see", "am seeing", "seeing", "sees"],
        answer: 1,
        explanation: "Fungsi Future Arrangement: Present Continuous digunakan untuk rencana pasti di masa depan. 'Am seeing' (akan menemui)."
    },
    {
        question: "She is ______ on the bed because she is tired.",
        options: ["lieing", "lying", "liying", "lie"],
        answer: 1,
        explanation: "Aturan ejaan: Kata kerja berakhiran '-ie' (lie), ubah 'ie' menjadi 'y' + ing. Jadi 'lying'."
    },
    {
        question: "We ______ to Paris next week. We have the tickets.",
        options: ["fly", "are flying", "flying", "flew"],
        answer: 1,
        explanation: "Rencana yang sudah pasti (sudah punya tiket) menggunakan Present Continuous untuk masa depan."
    },
    {
        question: "Usually I drive to work, but this week I ______ the bus.",
        options: ["take", "am taking", "taking", "takes"],
        answer: 1,
        explanation: "Temporary Situation: Untuk situasi sementara yang berbeda dari kebiasaan rutin (Usually), gunakan Present Continuous ('am taking')."
    },
    {
        question: "Why ______ you ______ ?",
        options: ["are / crying", "do / cry", "is / crying", "are / cry"],
        answer: 0,
        explanation: "Pertanyaan mengenai alasan aktivitas yang sedang terjadi sekarang: 'Why are you crying?'"
    },
    {
        question: "He ______ the truth.",
        options: ["isn't telling", "don't telling", "not telling", "isn't tells"],
        answer: 0,
        explanation: "Negatif Present Continuous: To Be + Not + V-ing. 'He isn't telling'."
    },
    {
        question: "The old man is ______ slowly.",
        options: ["dieing", "dying", "die", "died"],
        answer: 1,
        explanation: "Sama seperti 'lie', kata 'die' berubah menjadi 'dying'."
    },
    {
        question: "What ______ doing at the moment?",
        options: ["is she", "she is", "does she", "she does"],
        answer: 0,
        explanation: "Susunan kalimat tanya: Question Word + To Be + Subject + V-ing? -> 'What is she doing...?'"
    },
    {
        question: "I ______ with my aunt for a few days.",
        options: ["stay", "am staying", "staying", "stays"],
        answer: 1,
        explanation: "Situasi sementara (for a few days) menggunakan Present Continuous."
    },
    {
        question: "My computer ______ working properly.",
        options: ["isn't", "aren't", "don't", "doesn't"],
        answer: 0,
        explanation: "Subjek 'My computer' (tunggal/it) menggunakan 'is'. Bentuk negatif: 'isn't'."
    },
    {
        question: "Are they ______ a meeting now?",
        options: ["hold", "holding", "held", "holds"],
        answer: 1,
        explanation: "Setelah auxiliary 'Are', kata kerja harus V-ing."
    },
    {
        question: "The population of the world ______ very fast.",
        options: ["rise", "is rising", "rising", "are rising"],
        answer: 1,
        explanation: "Trends/Changes: Untuk perubahan bertahap, gunakan Present Continuous. Subjek 'Population' dianggap tunggal ('is rising')."
    },
    {
        question: "They ______ dinner party on Friday night.",
        options: ["are having", "have", "having", "had"],
        answer: 0,
        explanation: "Future arrangement (pesta yang sudah direncanakan)."
    },
    {
        question: "Who ______ you ______ for?",
        options: ["are / waiting", "do / wait", "is / waiting", "are / wait"],
        answer: 0,
        explanation: "Menanyakan siapa yang sedang ditunggu. 'Who are you waiting for?'"
    },
    {
        question: "Listen! Someone ______ to open the door.",
        options: ["try", "tries", "is trying", "are trying"],
        answer: 2,
        explanation: "Tanda seru 'Listen!' menandakan aksi saat ini. Subjek 'Someone' (indefinite pronoun) dianggap tunggal."
    },
    {
        question: "I ______ English this semester.",
        options: ["study", "am studying", "studies", "studying"],
        answer: 1,
        explanation: "Aktivitas yang terjadi dalam periode waktu sekitar sekarang (this semester), meski tidak tepat detik ini."
    },
    {
        question: "What are you ______ ?",
        options: ["makeing", "making", "make", "makes"],
        answer: 1,
        explanation: "Ejaan 'Make' -> 'Making' (buang e)."
    },
    {
        question: "My back hurts, so I ______ on the floor.",
        options: ["am lying", "am laying", "lie", "lay"],
        answer: 0,
        explanation: "'Lie' (berbaring) menjadi 'lying'. 'Laying' artinya meletakkan sesuatu."
    },
    {
        question: "______ coming to the cinema with us?",
        options: ["Is he", "Does he", "He is", "He does"],
        answer: 0,
        explanation: "Pertanyaan rencana masa depan (atau saat ini). Aux 'Is' di depan subjek 'he'."
    },
    {
        question: "The children ______ their costumes for the play.",
        options: ["putting on", "are putting on", "is putting on", "puts on"],
        answer: 1,
        explanation: "Subjek jamak 'children' pakai 'are'. 'Put' (CVC) double 't' -> 'putting'."
    },

    // --- LEVEL: EXPERT (10 Soal) ---
    // Fokus: Stative Verbs Traps, Dynamic meaning of state verbs, Annoyance with 'always', Passive.

    {
        question: "I ______ that you are right.",
        options: ["am believing", "believe", "believing", "was believing"],
        answer: 1,
        explanation: "Stative Verb Rule: Kata kerja 'Believe' adalah stative verb (kata kerja keadaan mental) yang TIDAK BOLEH dalam bentuk Continuous. Gunakan Simple Present."
    },
    {
        question: "Why are you smelling the milk? ______ it ______ bad?",
        options: ["Is / smelling", "Does / smell", "Is / smell", "Do / smelling"],
        answer: 1,
        explanation: "Dynamic vs Stative: 'Smelling' (aksi mencium bau) boleh continuous. Tapi 'Smell' (memiliki bau/beraroma) adalah stative, harus Simple Present ('Does it smell?')."
    },
    {
        question: "He ______ to be very rude today.",
        options: ["is appearing", "appears", "appearing", "appear"],
        answer: 1,
        explanation: "'Appear' (tampak/kelihatan) adalah stative verb di sini. Gunakan Simple Present. (Kecuali artinya 'tampil di panggung')."
    },
    {
        question: "I can't talk right now, I ______ dinner.",
        options: ["have", "am having", "having", "had"],
        answer: 1,
        explanation: "Dynamic 'Have': Ketika 'have' artinya 'makan' (activity), BOLEH di-ing-kan. Jika artinya 'memiliki' (possession), TIDAK BOLEH."
    },
    {
        question: "She ______ her keys. She ______ them everywhere.",
        options: ["is always losing / leaves", "always loses / is leaving", "is always losing / is leaving", "loses / leaves"],
        answer: 0,
        explanation: "Special Usage: 'Always' + Present Continuous digunakan untuk menyatakan kebiasaan yang MENGGANGGU (annoying habit). 'Is always losing' (menunjukkan kejengkelan)."
    },
    {
        question: "This sauce ______ great.",
        options: ["is tasting", "tastes", "taste", "tasting"],
        answer: 1,
        explanation: "'Taste' (terasa/memiliki rasa) adalah stative verb. 'I am tasting' (aksi mencicipi) boleh, tapi di sini subjeknya 'sauce', jadi 'tastes'."
    },
    {
        question: "You ______ very silly today. Usually you are serious.",
        options: ["are being", "are", "be", "being"],
        answer: 0,
        explanation: "To Be + Being + Adjective: Digunakan untuk perilaku SEMENTARA (temporary behaviour). 'You are being silly' artinya kamu bertingkah konyol (hanya saat ini)."
    },
    {
        question: "I ______ what you mean.",
        options: ["am understanding", "understand", "understanding", "understands"],
        answer: 1,
        explanation: "'Understand' adalah mental state verb, tidak digunakan dalam bentuk continuous."
    },
    {
        question: "The house ______ at the moment.",
        options: ["is painting", "is being painted", "paints", "painted"],
        answer: 1,
        explanation: "Passive Voice in Continuous: Rumusnya To Be + Being + V3. Rumah sedang dicat (pasif) -> 'is being painted'."
    },
    {
        question: "We ______ of buying a new car.",
        options: ["think", "are thinking", "thinking", "thoughts"],
        answer: 1,
        explanation: "'Think' di sini bermakna 'mempertimbangkan' (mental process/activity), bukan sekedar opini. Jadi BOLEH menggunakan continuous 'are thinking'."
    }
];