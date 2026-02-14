const questionsSource = [
    // --- LEVEL: BEGINNER (15 Soal) ---
    // Fokus: Mengenali struktur dasar "had been + V-ing"
    {
        question: "I ______ for two hours before the bus finally arrived.",
        options: ["have been waiting", "had been waiting", "was waiting", "am waiting"],
        answer: 1,
        explanation: "Struktur Past Perfect Continuous adalah 'had been + V-ing'. Kita menggunakan ini karena aksi menunggu terjadi selama durasi tertentu (two hours) sebelum kejadian lampau lain (bus arrived)."
    },
    {
        question: "She was tired because she ______ all day.",
        options: ["had been working", "has been working", "is working", "works"],
        answer: 0,
        explanation: "Kalimat utamanya 'She was tired' (Past Tense). Penyebabnya harus bentuk lampau yang menekankan durasi, yaitu 'had been working'."
    },
    {
        question: "They ______ football when it started to rain.",
        options: ["had been playing", "have played", "are playing", "play"],
        answer: 0,
        explanation: "Aksi bermain sudah berlangsung beberapa lama sebelum hujan turun di masa lampau. Polanya: had + been + playing."
    },
    {
        question: "He ______ English for three years before he moved to London.",
        options: ["has been studying", "had been studying", "studied", "studies"],
        answer: 1,
        explanation: "Ada durasi 'for three years' sebelum titik waktu lampau 'moved'. Maka digunakan Past Perfect Continuous: 'had been studying'."
    },
    {
        question: "My sister ______ knowing that the surprise party was cancelled.",
        options: ["had been crying", "has crying", "was cry", "had being crying"],
        answer: 0,
        explanation: "Bentuk yang benar secara gramatikal adalah 'had been crying'. Opsi lain salah secara struktur."
    },
    {
        question: "We ______ not ______ long when the accident happened.",
        options: ["had / driving", "have / driving", "had / been driving", "was / driving"],
        answer: 2,
        explanation: "Bentuk negatif Past Perfect Continuous: 'had not been V-ing'. Jadi jawabannya 'had / been driving'."
    },
    {
        question: "______ you ______ for me for a long time before I came?",
        options: ["Had / been waiting", "Have / been waiting", "Was / waiting", "Did / wait"],
        answer: 0,
        explanation: "Bentuk tanya (interrogative) Past Perfect Continuous dimulai dengan 'Had', diikuti subjek, lalu 'been V-ing'."
    },
    {
        question: "The ground was wet because it ______.",
        options: ["had been raining", "has been raining", "rains", "is raining"],
        answer: 0,
        explanation: "'The ground was wet' adalah Past Tense. Penyebabnya adalah hujan yang berlangsung sebelumnya, jadi 'had been raining'."
    },
    {
        question: "They ______ living in that house since 2010 before they sold it.",
        options: ["had been", "have been", "were", "are"],
        answer: 0,
        explanation: "Kita membutuhkan auxiliary 'had been' untuk melengkapi 'living' dalam konteks masa lampau sebelum 'sold'."
    },
    {
        question: "James ______ smoking for 10 years when he finally quit.",
        options: ["has been", "had been", "was", "is"],
        answer: 1,
        explanation: "Kejadian merokok berlangsung selama durasi (10 years) dan berakhir di masa lampau (quit). Gunakan 'had been'."
    },
    {
        question: "The baby ______ before her mother came home.",
        options: ["had sleeping", "had been sleeping", "has sleeping", "was slept"],
        answer: 1,
        explanation: "Pola yang benar adalah 'had been + V-ing' (sleeping)."
    },
    {
        question: "I ______ to fix the car for hours when help arrived.",
        options: ["had been trying", "have tried", "tried", "was try"],
        answer: 0,
        explanation: "Menunjukkan usaha yang berlangsung lama (for hours) sebelum bantuan datang di masa lalu."
    },
    {
        question: "______ she ______ TV all night?",
        options: ["Had / been watching", "Has / watched", "Was / watch", "Did / watching"],
        answer: 0,
        explanation: "Pertanyaan durasi di masa lampau: 'Had she been watching...?'"
    },
    {
        question: "We were hungry because we ______ anything all day.",
        options: ["had not been eating", "have not eaten", "are not eating", "do not eat"],
        answer: 0,
        explanation: "Alasan lapar di masa lampau (were hungry) adalah karena proses 'tidak makan' yang berlangsung seharian sebelumnya."
    },
    {
        question: "The athletes ______ training for months before the competition.",
        options: ["had been", "have been", "were", "are"],
        answer: 0,
        explanation: "Kegiatan 'training' berlangsung 'for months' sebelum 'competition'. Gunakan 'had been'."
    },

    // --- LEVEL: INTERMEDIATE (15 Soal) ---
    // Fokus: Membedakan dengan tenses lain, penekanan durasi (for, since), dan konteks cerita
    {
        question: "When I arrived at the office, Jane was exhausted. She ______ on the report since morning.",
        options: ["worked", "was working", "had been working", "has been working"],
        answer: 2,
        explanation: "Kita tidak menggunakan 'was working' (Past Continuous) karena ada penekanan durasi 'since morning' yang menyebabkan kelelahan setelahnya. Gunakan Past Perfect Continuous."
    },
    {
        question: "The road was blocked because the construction crew ______ it for three days.",
        options: ["had repaired", "had been repairing", "repaired", "were repairing"],
        answer: 1,
        explanation: "Fokusnya adalah pada durasi kegiatan (for three days) yang menyebabkan efek (blocked). 'Had repaired' fokus pada hasil selesai, 'Had been repairing' fokus pada prosesnya."
    },
    {
        question: "I realized that I ______ the wrong road for an hour.",
        options: ["was driving", "had been driving", "drove", "have driven"],
        answer: 1,
        explanation: "Kesadaran (realized) terjadi di masa lampau. Kegiatan menyetir terjadi *sebelum* kesadaran itu dan berlangsung selama satu jam."
    },
    {
        question: "She was out of breath because she ______.",
        options: ["ran", "had been running", "was running", "has run"],
        answer: 1,
        explanation: "Efek fisik (out of breath) di masa lampau biasanya disebabkan oleh aktivitas intens yang baru saja berhenti setelah berlangsung beberapa lama (had been running)."
    },
    {
        question: "By the time the police arrived, the thief ______ for 20 minutes.",
        options: ["had been hiding", "hid", "was hiding", "has been hiding"],
        answer: 0,
        explanation: "Frasa 'By the time' + Past Tense sering dipasangkan dengan Past Perfect Continuous jika ada durasi 'for 20 minutes'."
    },
    {
        question: "Ken gave up smoking two years ago. He ______ for 30 years.",
        options: ["smoked", "was smoking", "had been smoking", "has smoked"],
        answer: 2,
        explanation: "Aksi merokok terjadi sebelum 'two years ago' dan berlangsung selama durasi panjang (30 years). Past Perfect Continuous lebih tepat daripada Simple Past untuk menekankan durasi kebiasaan."
    },
    {
        question: "The band ______ for an hour when the electricity went out.",
        options: ["played", "had been playing", "were playing", "have played"],
        answer: 1,
        explanation: "Jika kita menggunakan 'were playing', kita hanya mengatakan mereka sedang bermain saat listrik mati. Tapi karena ada 'for an hour', kita harus menggunakan 'had been playing' untuk mengakomodasi durasinya."
    },
    {
        question: "How long ______ you ______ before you realized you lost your wallet?",
        options: ["had / been walking", "were / walking", "have / walked", "did / walk"],
        answer: 0,
        explanation: "Pertanyaan 'How long' di masa lampau sebelum kejadian lain (realized) menuntut Past Perfect Continuous."
    },
    {
        question: "The smell in the kitchen was terrible because something ______.",
        options: ["burned", "was burning", "had been burning", "has burned"],
        answer: 2,
        explanation: "'Was burning' berarti sedang terbakar saat itu. 'Had been burning' menyiratkan proses pembakaran sudah berlangsung sebelumnya dan menyebabkan bau tersebut."
    },
    {
        question: "They were annoyed because they ______ for the manager since 9 AM.",
        options: ["waited", "were waiting", "had been waiting", "have waited"],
        answer: 2,
        explanation: "Kunci: 'since 9 AM' digabungkan dengan konteks masa lampau (were annoyed)."
    },
    {
        question: "I ______ to get a hold of you all day yesterday!",
        options: ["had been trying", "have been trying", "tried", "was trying"],
        answer: 0,
        explanation: "Karena konteks waktunya 'yesterday' (sudah lewat), kita tidak bisa pakai 'have (Present)'. 'Had been trying' menekankan frustrasi atas durasi sepanjang hari."
    },
    {
        question: "He caught the flu because he ______ in the rain too long.",
        options: ["was walking", "had been walking", "walked", "has walked"],
        answer: 1,
        explanation: "Penyebab penyakit (caught flu) adalah durasi aktivitas sebelumnya (too long in the rain)."
    },
    {
        question: "When I met him, he looked different. He ______ out at the gym regularly.",
        options: ["had been working", "was working", "worked", "has been working"],
        answer: 0,
        explanation: "Perubahan penampilan adalah hasil dari proses berulang (regularly) yang terjadi *sebelum* pertemuan tersebut."
    },
    {
        question: "She didn't pass the exam even though she ______ very hard.",
        options: ["had been studying", "studied", "was studying", "has studied"],
        answer: 0,
        explanation: "Meskipun 'studied' (Simple Past) bisa benar, 'had been studying' lebih menekankan pada usaha terus-menerus yang dilakukan sebelum ujian."
    },
    {
        question: "The grass was yellow because it ______ all summer.",
        options: ["hadn't been raining", "didn't rain", "wasn't raining", "hasn't rained"],
        answer: 0,
        explanation: "Kondisi rumput kuning di masa lalu disebabkan oleh *absennya* hujan selama durasi panjang (all summer) sebelumnya."
    },

    // --- LEVEL: EXPERT (15 Soal) ---
    // Fokus: Kalimat kompleks, reported speech, inferensi (kesimpulan) tanpa penanda waktu eksplisit
    {
        question: "The detective knew that the suspect ______ because his story kept changing.",
        options: ["lied", "was lying", "had been lying", "has lied"],
        answer: 2,
        explanation: "Dalam Reported Speech atau pemikiran (knew), bentuk Present Perfect Continuous ('He has been lying') mundur menjadi Past Perfect Continuous ('He had been lying'). Menunjukkan pola kebohongan berulang."
    },
    {
        question: "I was startled to find that someone ______ my diary.",
        options: ["had been reading", "read", "was reading", "would read"],
        answer: 0,
        explanation: "Fokus pada *bukti* aktivitas yang baru saja selesai atau berulang tanpa sepengetahuan pembicara. 'Had been reading' menyiratkan seseorang melakukan itu dalam periode waktu sebelum diketahui."
    },
    {
        question: "Upon checking the records, we found that the software ______ data incorrectly for months.",
        options: ["was saving", "had been saving", "saved", "has been saving"],
        answer: 1,
        explanation: "Menemukan kesalahan (found) di masa lampau atas proses error yang sudah berlangsung lama (for months). Ini adalah masalah teknis berdurasi."
    },
    {
        question: "She felt betrayed because her partner ______ secrets from her.",
        options: ["was keeping", "kept", "had been keeping", "has kept"],
        answer: 2,
        explanation: "'Had been keeping' menekankan durasi penyembunyian rahasia yang mengarah pada perasaan dikhianati saat itu. Ini lebih kuat daripada 'kept' (sekali/fakta)."
    },
    {
        question: "The hikers were finally rescued. They ______ in the mountains for four days with no food.",
        options: ["wandered", "have been wandering", "had been wandering", "were wandering"],
        answer: 2,
        explanation: "Situasi kritis selesai (rescued). Kita melihat ke belakang pada durasi bertahan hidup (four days) sebelum penyelamatan."
    },
    {
        question: "Why did you change the channel? I ______ that program!",
        options: ["watched", "was watching", "had been watching", "have watched"],
        answer: 2,
        explanation: "Meskipun 'was watching' umum digunakan, 'had been watching' digunakan untuk menekankan keluhan bahwa aksi tersebut sudah berlangsung (dan dinikmati) sampai *terputus* oleh aksi orang lain (change channel)."
    },
    {
        question: "The pavement was slippery. It ______ , but it had stopped by the time we went out.",
        options: ["rained", "was raining", "had been raining", "rains"],
        answer: 2,
        explanation: "Ini adalah penggunaan klasik untuk *evidence in the present past*. Hujan sudah berhenti, tapi efeknya (licin) dan durasi sebelumnya disimpulkan menggunakan Past Perfect Continuous."
    },
    {
        question: "They decided to break up. They ______ incessantly for months.",
        options: ["argued", "were arguing", "had been arguing", "argue"],
        answer: 2,
        explanation: "Keputusan (decided) adalah puncaknya. Penyebabnya adalah argumen yang berulang-ulang dan berdurasi (incessantly for months)."
    },
    {
        question: "The engine was scalding hot. Clearly, someone ______ the car very hard.",
        options: ["drove", "was driving", "had been driving", "has driven"],
        answer: 2,
        explanation: "Kesimpulan logis (deduction) berdasarkan bukti fisik di masa lampau (hot engine). 'Someone had been driving' menjelaskan aktivitas intens yang baru saja berakhir."
    },
    {
        question: "He admitted that he ______ funds from the company accounts for years.",
        options: ["was stealing", "stole", "had been stealing", "had stolen"],
        answer: 2,
        explanation: "Kombinasi reported speech (admitted) + durasi panjang aktivitas kriminal (stealing for years). 'Had stolen' fokus pada jumlah/hasil, 'Had been stealing' fokus pada aktivitas berulang."
    },
    {
        question: "By 2020, Dr. Sastro ______ at the university for nearly forty years.",
        options: ["taught", "was teaching", "had been teaching", "has been teaching"],
        answer: 2,
        explanation: "Penanda waktu 'By [past year]' (By 2020) yang dipasangkan dengan durasi (for forty years) adalah indikator mutlak Past Perfect Continuous."
    },
    {
        question: "She ______ to finish the project by the deadline, but she fell ill.",
        options: ["hoped", "was hoping", "had been hoping", "has hoped"],
        answer: 2,
        explanation: "Menunjukkan harapan yang berlangsung terus-menerus sebelum akhirnya gagal karena sakit. Memberikan nuansa kekecewaan yang lebih dalam dibanding 'hoped'."
    },
    {
        question: "The weary travelers looked for a place to stay. They ______ since dawn.",
        options: ["were walking", "walked", "had been walking", "have walked"],
        answer: 2,
        explanation: "'Since dawn' memberikan titik mulai di masa lampau yang jauh dari saat narasi (looked for a place). Mengharuskan Past Perfect Continuous."
    },
    {
        question: "Whatever ______ in that laboratory caused a massive explosion.",
        options: ["they did", "they were doing", "they had been doing", "did they do"],
        answer: 2,
        explanation: "Subjek kalimat adalah klausa noun. Apa yang mereka lakukan (proses) menyebabkan ledakan. 'Had been doing' menekankan eksperimen/proses yang berlangsung hingga saat ledakan."
    },
    {
        question: "I wasn't surprised she won. She ______ for that specific role all her life.",
        options: ["prepared", "was preparing", "had been preparing", "has prepared"],
        answer: 2,
        explanation: "Persiapan seumur hidup (all her life) sebelum momen kemenangan di masa lalu. Ini adalah bentuk paling tepat untuk durasi yang sangat panjang sebelum titik lampau."
    }
];