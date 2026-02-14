const questionsSource = [
    // --- LEVEL BEGINNER (1-15) ---
    // Fokus: Struktur dasar (Was/Were + V-ing) dan Subject-Verb Agreement sederhana.

    {
        question: "I ______ watching TV at 8 PM last night.",
        options: ["were", "was", "am", "is"],
        answer: 1,
        explanation: "Subjek 'I' berpasangan dengan auxiliary verb 'was' dalam bentuk Past Continuous Tense."
    },
    {
        question: "They ______ playing football in the park yesterday afternoon.",
        options: ["was", "were", "are", "have"],
        answer: 1,
        explanation: "Subjek 'They' (jamak) berpasangan dengan 'were'. Keterangan waktu 'yesterday afternoon' menunjukkan masa lampau."
    },
    {
        question: "______ she sleeping when you got home?",
        options: ["Was", "Were", "Is", "Did"],
        answer: 0,
        explanation: "Dalam kalimat tanya Past Continuous, 'Was' digunakan di depan subjek tunggal 'she'."
    },
    {
        question: "We ______ not studying, we were playing games.",
        options: ["was", "were", "are", "did"],
        answer: 1,
        explanation: "Subjek 'We' (jamak) menggunakan 'were'. Kalimat ini menyangkal aktivitas yang sedang berlangsung di masa lampau."
    },
    {
        question: "The cat ______ chasing a mouse.",
        options: ["was", "were", "is", "had"],
        answer: 0,
        explanation: "Subjek 'The cat' (tunggal/it) menggunakan 'was' diikuti verb-ing."
    },
    {
        question: "It ______ raining heavily all night.",
        options: ["were", "was", "is", "has"],
        answer: 1,
        explanation: "Subjek 'It' (cuaca/keadaan) menggunakan 'was' dalam konteks masa lampau."
    },
    {
        question: "What ______ you doing at this time yesterday?",
        options: ["was", "were", "are", "did"],
        answer: 1,
        explanation: "Subjek 'you' selalu berpasangan dengan 'were', baik dalam pernyataan maupun pertanyaan."
    },
    {
        question: "My parents ______ having dinner when I called.",
        options: ["was", "were", "are", "have"],
        answer: 1,
        explanation: "Subjek 'My parents' (jamak) memerlukan 'were' sebagai auxiliary verb."
    },
    {
        question: "He ______ reading a book in the library.",
        options: ["were", "was", "is", "does"],
        answer: 1,
        explanation: "Subjek 'He' (tunggal) menggunakan 'was'."
    },
    {
        question: "The baby ______ crying loudly.",
        options: ["were", "was", "are", "do"],
        answer: 1,
        explanation: "Subjek 'The baby' (tunggal) menggunakan 'was'."
    },
    {
        question: "You ______ not listening to me.",
        options: ["was", "were", "is", "did"],
        answer: 1,
        explanation: "Kalimat negatif Past Continuous untuk subjek 'You' menggunakan 'were not' (weren't)."
    },
    {
        question: "______ John and Sarah working on the project?",
        options: ["Was", "Were", "Are", "Did"],
        answer: 1,
        explanation: "Subjeknya adalah 'John and Sarah' (jamak/they), jadi menggunakan 'Were'."
    },
    {
        question: "The sun ______ shining brightly that morning.",
        options: ["was", "were", "is", "has"],
        answer: 0,
        explanation: "Subjek 'The sun' (tunggal) menggunakan 'was'."
    },
    {
        question: "Who ______ driving the car?",
        options: ["was", "were", "are", "do"],
        answer: 0,
        explanation: "Ketika menanyakan subjek tunggal (siapa), kita biasanya menggunakan 'was' sebagai default."
    },
    {
        question: "I ______ waiting for the bus for 20 minutes.",
        options: ["were", "was", "am", "have"],
        answer: 1,
        explanation: "Bentuk dasar Past Continuous untuk subjek 'I' adalah 'was waiting'."
    },

    // --- LEVEL INTERMEDIATE (16-30) ---
    // Fokus: Penggunaan 'When' vs 'While', aksi yang terinterupsi, dan dua aksi bersamaan.

    {
        question: "I was cooking dinner ______ the phone rang.",
        options: ["while", "when", "during", "at"],
        answer: 1,
        explanation: "'When' biasanya diikuti oleh Simple Past (the phone rang) untuk menunjukkan aksi singkat yang memotong aksi yang sedang berlangsung."
    },
    {
        question: "______ I was walking to school, I saw an accident.",
        options: ["When", "While", "Where", "Because"],
        answer: 1,
        explanation: "'While' biasanya diikuti oleh Past Continuous (I was walking) untuk menunjukkan durasi atau proses."
    },
    {
        question: "She cut her finger while she ______ vegetables.",
        options: ["chopped", "was chopping", "is chopping", "chops"],
        answer: 1,
        explanation: "Klausa setelah 'while' membutuhkan Past Continuous ('was chopping') untuk menunjukkan aksi yang sedang terjadi saat insiden (cut finger) terjadi."
    },
    {
        question: "They ______ cards when the lights went out.",
        options: ["played", "were playing", "have played", "are playing"],
        answer: 1,
        explanation: "Aksi bermain kartu sedang berlangsung ('were playing') sebelum diinterupsi oleh lampu mati."
    },
    {
        question: "While the teacher was explaining, the students ______ notes.",
        options: ["took", "were taking", "take", "have taken"],
        answer: 1,
        explanation: "Dua aksi yang terjadi bersamaan (Parallel Actions) di masa lampau sama-sama menggunakan Past Continuous."
    },
    {
        question: "He ______ his bike when he fell.",
        options: ["rode", "was riding", "is riding", "rides"],
        answer: 1,
        explanation: "Aksi mengendarai sepeda sedang berlangsung ('was riding') ketika dia jatuh (Simple Past)."
    },
    {
        question: "The music ______ loud when we entered the room.",
        options: ["was playing", "played", "is playing", "plays"],
        answer: 0,
        explanation: "Musik sedang berbunyi ('was playing') sebagai latar belakang kejadian saat kami masuk."
    },
    {
        question: "What were you doing when the earthquake ______?",
        options: ["starting", "start", "started", "was starting"],
        answer: 2,
        explanation: "Klausa 'when' biasanya diikuti Simple Past ('started') sebagai penanda waktu spesifik kejadian singkat."
    },
    {
        question: "I saw you in the park. You ______ on a bench.",
        options: ["sat", "were sitting", "are sitting", "have sat"],
        answer: 1,
        explanation: "Menggambarkan apa yang sedang subjek lakukan pada momen tertentu di masa lampau menggunakan Past Continuous."
    },
    {
        question: "While mom was reading, dad ______ dinner.",
        options: ["cooked", "was cooking", "cooks", "is cooking"],
        answer: 1,
        explanation: "Dua aktivitas berdurasi panjang yang terjadi bersamaan dihubungkan dengan 'while' biasanya keduanya memakai Past Continuous."
    },
    {
        question: "The car engine ______ a strange noise while we were driving.",
        options: ["made", "was making", "makes", "has made"],
        answer: 1,
        explanation: "Mesin 'sedang membuat' suara aneh selama proses menyetir berlangsung."
    },
    {
        question: "We ______ about the movie when he interrupted us.",
        options: ["talked", "were talking", "talk", "have talked"],
        answer: 1,
        explanation: "Aksi berbicara sedang berlangsung ('were talking') sebelum diinterupsi."
    },
    {
        question: "______ you listening when I told you the answer?",
        options: ["Did", "Was", "Were", "Are"],
        answer: 2,
        explanation: "Pertanyaan Past Continuous 'Apakah kamu sedang mendengarkan...' menggunakan 'Were you...?'."
    },
    {
        question: "At 10 AM yesterday, I ______ a meeting.",
        options: ["attended", "was attending", "am attending", "attend"],
        answer: 1,
        explanation: "Keterangan waktu spesifik 'At 10 AM yesterday' menekankan bahwa aksi sedang berlangsung tepat pada jam itu."
    },
    {
        question: "He wasn't working, he ______ a break.",
        options: ["took", "was taking", "takes", "is taking"],
        answer: 1,
        explanation: "Kalimat ini mengoreksi aktivitas yang sedang terjadi: bukan bekerja, tapi sedang istirahat."
    },

    // --- LEVEL EXPERT (31-45) ---
    // Fokus: Passive Voice, Konteks kompleks, "Always" untuk keluhan, dan pengecoh (Stative Verbs).

    {
        question: "The old building ______ renovated when I passed by.",
        options: ["was being", "was", "is being", "had been"],
        answer: 0,
        explanation: "Bentuk Pasif dari Past Continuous adalah 'was/were + being + V3'. Gedung sedang direnovasi."
    },
    {
        question: "He was always ______ about his job, which was annoying.",
        options: ["complained", "complaining", "complain", "complains"],
        answer: 1,
        explanation: "Past Continuous dengan 'always' digunakan untuk mengekspresikan kebiasaan di masa lalu yang mengganggu (irritation)."
    },
    {
        question: "While the contract ______, the partners discussed the terms.",
        options: ["was typed", "was being typed", "typed", "is being typed"],
        answer: 1,
        explanation: "Pasif: Kontrak sedang diketik ('was being typed') sementara diskusi berlangsung."
    },
    {
        question: "I realized that someone ______ me.",
        options: ["was following", "follows", "is following", "followed"],
        answer: 0,
        explanation: "Konteks 'realized' (Past) menuntut aksi yang sedang terjadi saat itu juga dalam bentuk lampau ('was following')."
    },
    {
        question: "The guests ______ by the host when the power failed.",
        options: ["were entertained", "were being entertained", "entertained", "had entertained"],
        answer: 1,
        explanation: "Pasif: Para tamu 'sedang dihibur' ('were being entertained') saat lampu mati."
    },
    {
        question: "She looked as if she ______ the truth.",
        options: ["was not telling", "did not tell", "is not telling", "has not told"],
        answer: 0,
        explanation: "Menggambarkan kesan bahwa seseorang sedang melakukan sesuatu (berbohong/tidak jujur) pada saat itu."
    },
    {
        question: "Why ______ the dog ______ barking at the empty corner?",
        options: ["was / continuously", "did / continuously", "is / continuously", "had / continuously"],
        answer: 0,
        explanation: "Menanyakan aksi yang sedang berlangsung terus-menerus di masa lampau: 'Why was the dog continuously barking?'"
    },
    {
        question: "At this time last year, we ______ in Europe.",
        options: ["traveled", "were traveling", "have traveled", "travel"],
        answer: 1,
        explanation: "Penanda waktu 'At this time last year' sangat spesifik untuk menekankan durasi yang sedang berjalan di masa lalu."
    },
    {
        question: "The suspect claimed he ______ at home at the time of the crime.",
        options: ["was sleeping", "slept", "is sleeping", "has slept"],
        answer: 0,
        explanation: "Alibi biasanya menjelaskan apa yang 'sedang dilakukan' pada waktu spesifik kejadian."
    },
    {
        question: "They ______ attention to the lecture, so they failed the test.",
        options: ["weren't paying", "didn't pay", "haven't paid", "aren't paying"],
        answer: 0,
        explanation: "Menjelaskan alasan kegagalan: proses 'tidak memperhatikan' yang berlangsung selama kuliah."
    },
    {
        question: "The issue ______ discussed when the director walked out.",
        options: ["was being", "is being", "was", "had been"],
        answer: 0,
        explanation: "Pasif: Masalah 'sedang didiskusikan' ('was being discussed')."
    },
    {
        question: "My computer ______ updates when I tried to shut it down.",
        options: ["installed", "was installing", "is installing", "installs"],
        answer: 1,
        explanation: "Komputer sedang dalam proses menginstall update saat tombol shutdown ditekan."
    },
    {
        question: "None of the equipment ______ properly during the experiment.",
        options: ["was working", "were working", "worked", "is working"],
        answer: 0,
        explanation: "'Equipment' adalah uncountable noun (dianggap tunggal), jadi menggunakan 'was working'. Fokus pada durasi eksperimen."
    },
    {
        question: "While I ______ to the radio, I heard the breaking news.",
        options: ["listened", "was listening", "am listening", "have listened"],
        answer: 1,
        explanation: "Aksi latar belakang (mendengarkan radio) menggunakan Past Continuous sebelum info penting (breaking news) terdengar."
    },
    {
        question: "The crowd ______ impatient as they waited for the band.",
        options: ["was getting", "got", "is getting", "gets"],
        answer: 0,
        explanation: "Menunjukkan proses perubahan bertahap (becoming/getting) yang sedang berlangsung di masa lalu."
    }
];