const questionsSource = [
  {
        question: "By next year, I ______ here for ten years.",
        options: ["will have been working", "will work", "am working", "worked"],
        answer: 0,
        explanation: "Kalimat ini menggunakan 'By next year' dan durasi 'for ten years', yang merupakan ciri khas Future Perfect Continuous Tense (akan sudah sedang berlangsung). Rumusnya: will + have + been + V-ing."
    },
    {
        question: "She ______ for you when you arrive at the station.",
        options: ["will have been waiting", "wait", "waits", "is waiting"],
        answer: 0,
        explanation: "Kita menekankan durasi tindakan yang masih akan berlangsung saat kejadian lain terjadi di masa depan. Struktur yang benar adalah 'will have been waiting'."
    },
    {
        question: "They ______ soccer for two hours by the time the sun sets.",
        options: ["will play", "will have been playing", "are playing", "played"],
        answer: 1,
        explanation: "Adanya penanda waktu 'by the time...' dan durasi 'for two hours' mengharuskan penggunaan Future Perfect Continuous Tense."
    },
    {
        question: "In December, we ______ in this house for five years.",
        options: ["will have been living", "will live", "live", "have lived"],
        answer: 0,
        explanation: "Untuk menyatakan durasi tinggal yang akan genap 5 tahun di masa depan (Desember), kita gunakan 'will have been living'."
    },
    {
        question: "By 8 PM, he ______ for 12 hours straight.",
        options: ["will sleep", "is sleeping", "will have been sleeping", "slept"],
        answer: 2,
        explanation: "Fokus pada durasi aktivitas (tidur) yang akan telah terjadi pada titik waktu tertentu di masa depan (jam 8 malam)."
    },
    {
        question: "Next month, I ______ English for exactly three years.",
        options: ["study", "will have been studying", "am studying", "will be studying"],
        answer: 1,
        explanation: "Penanda 'for exactly three years' pada waktu di masa depan ('Next month') menunjukkan Future Perfect Continuous."
    },
    {
        question: "My father ______ at that company for 20 years by the time he retires.",
        options: ["will have been working", "works", "is working", "worked"],
        answer: 0,
        explanation: "Menggambarkan durasi kerja yang akan genap 20 tahun pada saat pensiun nanti."
    },
    {
        question: "______ they ______ together for long when they graduate?",
        options: ["Will / have been playing", "Do / play", "Are / playing", "Did / play"],
        answer: 0,
        explanation: "Bentuk pertanyaan (interrogative) dari Future Perfect Continuous adalah: Will + S + have been + V-ing."
    },
    {
        question: "By tomorrow morning, it ______ for three days continuously.",
        options: ["will rain", "will have been raining", "rains", "is raining"],
        answer: 1,
        explanation: "Menyatakan durasi hujan yang akan mencapai 3 hari pada besok pagi."
    },
    {
        question: "You ______ for over an hour by the time the bus finally gets here.",
        options: ["will wait", "will have been waiting", "waiting", "have waited"],
        answer: 1,
        explanation: "Gabungan 'by the time' dan durasi 'for over an hour' mengarah pada Future Perfect Continuous."
    },
    {
        question: "The athletes ______ for months before the Olympics begin.",
        options: ["will have been training", "train", "will train", "are training"],
        answer: 0,
        explanation: "Menunjukkan durasi latihan yang terus berlangsung hingga event dimulai."
    },
    {
        question: "I ______ this book for a week by Sunday.",
        options: ["read", "am reading", "will have been reading", "have read"],
        answer: 2,
        explanation: "Target waktu 'by Sunday' dengan durasi 'for a week' memerlukan 'will have been reading'."
    },
    {
        question: "By next week, she ______ on her project for a whole month.",
        options: ["will have been working", "will work", "is working", "worked"],
        answer: 0,
        explanation: "Durasi 'for a whole month' yang terpenuhi di masa depan ('by next week') menggunakan struktur ini."
    },
    {
        question: "We ______ TV for four hours when mom comes home.",
        options: ["will watch", "will have been watching", "are watching", "watch"],
        answer: 1,
        explanation: "Menyatakan aktivitas menonton yang sudah berlangsung selama durasi tertentu saat kejadian lain terjadi."
    },
    {
        question: "He ______ driving for six hours by the time he reaches the border.",
        options: ["will have been", "will be", "is", "has been"],
        answer: 0,
        explanation: "Kata kerja utamanya adalah 'driving', jadi kita butuh auxiliary 'will have been' untuk melengkapinya."
    },

    // --- INTERMEDIATE LEVEL (16-30) ---
    // Fokus: Variasi kalimat negatif, interogatif, dan konteks waktu yang lebih spesifik.
    {
        question: "Won't you ______ tired after you will have been driving all day?",
        options: ["be", "have been", "been", "being"],
        answer: 0,
        explanation: "Ini adalah jebakan struktur. Bagian pertama adalah Future Simple ('Won't you be tired'), bagian kedua adalah Future Perfect Continuous sebagai penyebab."
    },
    {
        question: "By the end of this course, how long ______ learning Spanish?",
        options: ["will you have been", "have you been", "will you be", "are you"],
        answer: 0,
        explanation: "Pertanyaan durasi (how long) yang berorientasi ke masa depan (by the end of this course) memerlukan inversi subjek: Will + you + have been..."
    },
    {
        question: "She ______ much longer by the time we arrive, so she might be angry.",
        options: ["won't have been waiting", "will have been waiting", "waits", "is waiting"],
        answer: 1,
        explanation: "Konteks kalimat 'so she might be angry' menyiratkan dia sudah menunggu lama, jadi bentuk positif 'will have been waiting' lebih tepat."
    },
    {
        question: "Next year, I ______ vegan for exactly a decade.",
        options: ["will have been being", "will have been", "am being", "will be"],
        answer: 1,
        explanation: "Pengecualian! 'Be' adalah stative verb yang jarang/tidak umum digunakan dalam bentuk continuous ('been being'). Gunakan Future Perfect biasa: 'will have been'."
    },
    {
        question: "They ______ the problem for hours, yet they won't have found a solution.",
        options: ["will have been discussing", "will discuss", "are discussing", "have discussed"],
        answer: 0,
        explanation: "Menunjukkan durasi diskusi yang panjang di masa depan, meskipun hasilnya belum ada."
    },
    {
        question: "I suppose James ______ the news when we get there.",
        options: ["will have been watching", "will watch", "is watching", "watches"],
        answer: 0,
        explanation: "Prediksi (suppose) tentang aktivitas yang sedang berlangsung dan memiliki durasi saat kita tiba."
    },
    {
        question: "By 2026, scientists ______ for a cure for over 50 years.",
        options: ["will search", "will have been searching", "have searched", "are searching"],
        answer: 1,
        explanation: "Menekankan durasi pencarian yang sangat panjang hingga titik waktu di masa depan."
    },
    {
        question: "If you come at noon, I ______ cooking, so the kitchen will be messy.",
        options: ["will have been", "will be", "am", "was"],
        answer: 0,
        explanation: "Konteks 'kitchen will be messy' menunjukkan konsekuensi dari aktivitas yang telah berlangsung terus-menerus (will have been cooking)."
    },
    {
        question: "How long ______ when the alarm finally goes off?",
        options: ["will you have been sleeping", "will you sleep", "do you sleep", "are you sleeping"],
        answer: 0,
        explanation: "Pertanyaan spesifik tentang durasi tidur hingga kejadian lain (alarm berbunyi) terjadi."
    },
    {
        question: "We ______ for the exam all night, so we'll need coffee in the morning.",
        options: ["will have been studying", "will study", "study", "are studying"],
        answer: 0,
        explanation: "Sebab-akibat di masa depan. Butuh kopi karena 'will have been studying' sepanjang malam."
    },
    {
        question: "By the time the manager arrives, the team ______ the proposal for three hours.",
        options: ["will have been drafting", "will draft", "drafts", "has drafted"],
        answer: 0,
        explanation: "Pola klasik: By + time clause (Simple Present) -> Main clause (Future Perfect Continuous)."
    },
    {
        question: "She ______ in the marathon, so she will be exhausted.",
        options: ["will have been running", "will run", "runs", "ran"],
        answer: 0,
        explanation: "Alasan kelelahan di masa depan adalah durasi lari yang telah dilakukan."
    },
    {
        question: "My parents ______ for 30 years next anniversary.",
        options: ["will have been married", "will have been marrying", "will marry", "are married"],
        answer: 0,
        explanation: "Pengecualian Stative! 'Married' adalah adjektiva/kondisi, bukan aksi duratif. Gunakan Future Perfect Tense, bukan Continuous."
    },
    {
        question: "Do you think she ______ when we ring the doorbell?",
        options: ["will have been sleeping", "will sleep", "sleeps", "is sleeping"],
        answer: 0,
        explanation: "Memprediksi aktivitas yang sedang berlangsung dalam durasi tertentu saat gangguan terjadi."
    },
    {
        question: "By the time you read this letter, I ______ far away.",
        options: ["will have been flying", "will fly", "fly", "am flying"],
        answer: 0,
        explanation: "Menyiratkan proses perjalanan (flying) yang sudah berlangsung beberapa lama saat surat dibaca."
    },

    // --- EXPERT LEVEL (31-45) ---
    // Fokus: Pengecualian (Stative Verbs), Nuansa makna, dan kalimat majemuk kompleks.
    {
        question: "Even though he is tired, by midnight he ______ on his thesis for 16 hours.",
        options: ["will have been working", "will have worked", "is working", "works"],
        answer: 0,
        explanation: "Menekankan *kelangsungan* dan *durasi* ekstrem (16 jam) yang menyebabkan kelelahan, lebih tepat menggunakan Continuous daripada Perfect biasa."
    },
    {
        question: "By next month, I ______ the owner of this car for five years.",
        options: ["will have been being", "will have been", "will be", "am being"],
        answer: 1,
        explanation: "Jebakan Stative Verb. Kata kerja kepemilikan atau kondisi (be/own/know) tidak bisa dalam bentuk continuous. Gunakan Future Perfect: 'will have been'."
    },
    {
        question: "They ______ constructing the bridge for two years by the time the funding runs out.",
        options: ["will have been", "will be", "have been", "are"],
        answer: 0,
        explanation: "Struktur lengkapnya adalah 'will have been constructing'. Opsi yang tersedia hanya auxiliary-nya."
    },
    {
        question: "When you finally arrive, ______ waiting for more than two hours?",
        options: ["will we have been", "will we be", "are we", "have we been"],
        answer: 0,
        explanation: "Interrogative inversion yang benar untuk Future Perfect Continuous: Will + S + have been + V-ing."
    },
    {
        question: "I ______ the violin well enough to perform, even after I ______ practicing for years.",
        options: ["won't play / will have been", "won't have been playing / will be", "don't play / have been", "won't play / have been"],
        answer: 0,
        explanation: "Kombinasi tenses. Klausa pertama Future Simple (kemampuan), klausa kedua Future Perfect Continuous (durasi latihan di masa depan)."
    },
    {
        question: "By the time the project ends, we ______ various obstacles for months.",
        options: ["will have been overcoming", "will overcome", "will have overcome", "overcome"],
        answer: 0,
        explanation: "Menggambarkan proses berulang (overcoming obstacles) yang terus menerus dilakukan selama berbulan-bulan."
    },
    {
        question: "She ______ the layout for days, but she still won't be satisfied.",
        options: ["will have been designing", "will design", "designs", "is designing"],
        answer: 0,
        explanation: "Kontras antara durasi usaha (will have been designing) dan hasil (won't be satisfied)."
    },
    {
        question: "Next week, I ______ this confusing novel for a month; I hope to finish it soon.",
        options: ["will have been reading", "will read", "am reading", "have read"],
        answer: 0,
        explanation: "Fokus pada proses membaca yang belum selesai (ongoing) meskipun sudah berjalan sebulan."
    },
    {
        question: "By the time the verdict is announced, the jury ______ for three days.",
        options: ["will have been deliberating", "will deliberate", "are deliberating", "have deliberated"],
        answer: 0,
        explanation: "'Deliberating' adalah kata kerja duratif yang tepat untuk konteks juri, menggunakan Future Perfect Continuous."
    },
    {
        question: "We can't meet at 5 PM because I ______ then.",
        options: ["will have been working out", "will work out", "work out", "have worked out"],
        answer: 0,
        explanation: "Selain durasi, tense ini bisa menyiratkan bahwa pada jam 5 sore, aktivitas tersebut masih sedang berlangsung (dan sudah mulai sebelumnya)."
    },
    {
        question: "Assume that by 2030, humans ______ strictly on renewable energy for a decade?",
        options: ["will have been relying", "will rely", "rely", "are relying"],
        answer: 0,
        explanation: "Pertanyaan hipotetis tentang masa depan dengan durasi 'for a decade'."
    },
    {
        question: "Use simple logic: If you start at 1 PM and I come at 4 PM, you ______ for 3 hours.",
        options: ["will have been waiting", "wait", "are waiting", "waited"],
        answer: 0,
        explanation: "Logika deduksi waktu di masa depan yang mengharuskan penggunaan tense ini."
    },
    {
        question: "By the time he understands the truth, we ______ to him for weeks.",
        options: ["will have been lying", "will lie", "are lying", "have lied"],
        answer: 0,
        explanation: "Menyiratkan tindakan 'berbohong' yang berlanjut terus menerus hingga titik dia sadar."
    },
    {
        question: "I ______ anything all day by dinner time, so I'll be starving.",
        options: ["won't have been eating", "won't eat", "not eating", "don't eat"],
        answer: 0,
        explanation: "Bentuk negatif: Menekankan *absennya* aktivitas (makan) secara terus menerus sepanjang hari hingga makan malam."
    },
    {
        question: "Unlike his brother, by age 25, Tom ______ his own business for 5 years.",
        options: ["will have been running", "will run", "runs", "is running"],
        answer: 0,
        explanation: "Perbandingan konteks masa depan dengan durasi spesifik kepemilikan bisnis (running a business)."
    }
];