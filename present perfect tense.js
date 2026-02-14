const questionsSource = [
    // --- LEVEL: BEGINNER (20 Soal) ---
    // Fokus: Struktur dasar (S + have/has + V3), pemilihan auxiliary, dan bentuk V3 umum.

    {
        question: "I ______ finished my homework.",
        options: ["have", "has", "am", "was"],
        answer: 0,
        explanation: "Subjek 'I' selalu menggunakan auxiliary 'have' dalam Present Perfect Tense. Polanya: I + have + V3."
    },
    {
        question: "She ______ visited Paris twice.",
        options: ["have", "has", "is", "was"],
        answer: 1,
        explanation: "Subjek tunggal (singular) 'She' menggunakan auxiliary 'has'. Polanya: She + has + V3."
    },
    {
        question: "They ______ cleaned the room.",
        options: ["has", "have", "are", "were"],
        answer: 1,
        explanation: "Subjek jamak (plural) 'They' menggunakan auxiliary 'have'. Polanya: They + have + V3."
    },
    {
        question: "He has ______ a new car.",
        options: ["buy", "bought", "buying", "buys"],
        answer: 1,
        explanation: "Setelah auxiliary 'has', kata kerja harus dalam bentuk Past Participle (V3). V3 dari 'buy' adalah 'bought'."
    },
    {
        question: "We have ______ this movie before.",
        options: ["see", "saw", "seen", "seeing"],
        answer: 2,
        explanation: "Setelah 'have', kita butuh V3. Bentuk V3 dari 'see' adalah 'seen'. (See - Saw - Seen)."
    },
    {
        question: "______ you ever eaten Sushi?",
        options: ["Has", "Have", "Do", "Did"],
        answer: 1,
        explanation: "Untuk kalimat tanya dengan subjek 'You', gunakan auxiliary 'Have' di awal kalimat."
    },
    {
        question: "The train ______ arrived at the station.",
        options: ["have", "has", "is", "was"],
        answer: 1,
        explanation: "Subjek 'The train' adalah tunggal (kata benda/it), jadi menggunakan auxiliary 'has'."
    },
    {
        question: "My parents ______ lived here for 20 years.",
        options: ["has", "have", "are", "do"],
        answer: 1,
        explanation: "Subjek 'My parents' adalah jamak (lebih dari satu), setara dengan 'they', jadi menggunakan 'have'."
    },
    {
        question: "John ______ not called me yet.",
        options: ["have", "has", "is", "does"],
        answer: 1,
        explanation: "Subjek 'John' (orang ketiga tunggal) menggunakan 'has'. Bentuk negatifnya menjadi 'has not'."
    },
    {
        question: "I have ______ my keys.",
        options: ["lose", "lost", "losing", "losed"],
        answer: 1,
        explanation: "Kata kerja setelah 'have' harus V3. V3 dari 'lose' adalah 'lost'."
    },
    {
        question: "______ she done her work?",
        options: ["Have", "Has", "Is", "Does"],
        answer: 1,
        explanation: "Kalimat tanya dengan subjek 'She' dimulai dengan auxiliary 'Has'."
    },
    {
        question: "We ______ never been to Japan.",
        options: ["has", "have", "are", "were"],
        answer: 1,
        explanation: "Subjek 'We' menggunakan 'have'. Struktur: We + have + never + V3."
    },
    {
        question: "It has ______ raining.",
        options: ["stop", "stopped", "stopping", "stops"],
        answer: 1,
        explanation: "Setelah 'has', gunakan V3. Kata kerja 'stop' adalah regular verb, jadi V3-nya 'stopped'."
    },
    {
        question: "You ______ broken the glass!",
        options: ["has", "have", "are", "did"],
        answer: 1,
        explanation: "Subjek 'You' dipasangkan dengan 'have' dalam Present Perfect."
    },
    {
        question: "The students ______ passed the exam.",
        options: ["has", "have", "are", "is"],
        answer: 1,
        explanation: "Subjek 'The students' (jamak/banyak siswa) menggunakan 'have'."
    },
    {
        question: "Bob and Alice ______ met each other.",
        options: ["has", "have", "are", "were"],
        answer: 1,
        explanation: "Subjek gabungan 'Bob and Alice' adalah jamak (mereka), jadi menggunakan 'have'."
    },
    {
        question: "She has ______ a letter to her friend.",
        options: ["write", "wrote", "written", "writing"],
        answer: 2,
        explanation: "V3 dari 'write' adalah 'written'. (Write - Wrote - Written)."
    },
    {
        question: "______ they finished the game?",
        options: ["Has", "Have", "Are", "Do"],
        answer: 1,
        explanation: "Pertanyaan dengan subjek 'they' dimulai dengan 'Have'."
    },
    {
        question: "The dog has ______ all the food.",
        options: ["eat", "ate", "eaten", "eating"],
        answer: 2,
        explanation: "V3 dari 'eat' adalah 'eaten'. (Eat - Ate - Eaten)."
    },
    {
        question: "I have ______ that book.",
        options: ["read", "reads", "reading", "red"],
        answer: 0,
        explanation: "V3 dari 'read' tulisannya tetap 'read' (meski dibaca 'red'). Jadi 'have read'."
    },

    // --- LEVEL: INTERMEDIATE (20 Soal) ---
    // Fokus: Time signals (Since, For, Just, Yet, Already), posisi adverb, dan kalimat negatif.

    {
        question: "I have lived in this city ______ 2010.",
        options: ["for", "since", "in", "at"],
        answer: 1,
        explanation: "Gunakan 'since' untuk menunjukkan titik awal waktu (starting point) dari suatu kejadian."
    },
    {
        question: "We have known each other ______ ten years.",
        options: ["since", "for", "during", "while"],
        answer: 1,
        explanation: "Gunakan 'for' untuk menunjukkan durasi atau rentang waktu (a period of time)."
    },
    {
        question: "Have you finished your homework ______?",
        options: ["just", "already", "yet", "since"],
        answer: 2,
        explanation: "Kata 'yet' digunakan dalam kalimat tanya (interrogative) dan negatif, biasanya diletakkan di akhir kalimat."
    },
    {
        question: "She has ______ left the office.",
        options: ["yet", "just", "since", "ever"],
        answer: 1,
        explanation: "'Just' digunakan untuk menyatakan kejadian yang baru saja terjadi. Posisinya di antara auxiliary (has) dan V3 (left)."
    },
    {
        question: "I haven't seen him ______ last week.",
        options: ["for", "since", "until", "by"],
        answer: 1,
        explanation: "'Last week' adalah titik waktu spesifik, jadi gunakan 'since'."
    },
    {
        question: "They have ______ eaten lunch, so they are not hungry.",
        options: ["yet", "already", "since", "ever"],
        answer: 1,
        explanation: "'Already' digunakan untuk menyatakan sesuatu sudah terjadi (lebih cepat dari dugaan atau menekankan fakta). Posisinya di antara have dan V3."
    },
    {
        question: "He hasn't arrived ______.",
        options: ["just", "already", "yet", "never"],
        answer: 2,
        explanation: "Dalam kalimat negatif (hasn't), gunakan 'yet' di akhir kalimat untuk menyatakan 'belum'."
    },
    {
        question: "______ you ever been to Bali?",
        options: ["Has", "Did", "Have", "Do"],
        answer: 2,
        explanation: "Frasa 'Have you ever...' adalah bentuk standar menanyakan pengalaman hidup. 'Ever' diletakkan sebelum V3."
    },
    {
        question: "We have lived here ______ a long time.",
        options: ["since", "for", "in", "from"],
        answer: 1,
        explanation: "'A long time' adalah durasi waktu, jadi pasangannya adalah 'for'."
    },
    {
        question: "She has never ______ a horse before.",
        options: ["rode", "ridden", "ride", "riding"],
        answer: 1,
        explanation: "V3 dari 'ride' adalah 'ridden'. Pola: has + never + V3."
    },
    {
        question: "I have ______ met him at the party.",
        options: ["just", "yet", "since", "for"],
        answer: 0,
        explanation: "Konteks 'baru saja bertemu'. 'Just' adalah adverb yang paling tepat disisipkan di sini."
    },
    {
        question: "Has the class started ______?",
        options: ["just", "already", "yet", "since"],
        answer: 2,
        explanation: "Pertanyaan 'Apakah sudah dimulai?'. Gunakan 'yet' di akhir kalimat tanya."
    },
    {
        question: "They ______ gone to the cinema.",
        options: ["have just", "has just", "did just", "are just"],
        answer: 0,
        explanation: "Subjek 'They' butuh 'have'. 'Just' disisipkan setelahnya. Jadi 'have just'."
    },
    {
        question: "My father has worked in that company ______ he was 25.",
        options: ["for", "since", "when", "until"],
        answer: 1,
        explanation: "Klausa 'he was 25' menandakan titik waktu awal di masa lalu. Gunakan 'since' diikuti klausa Past Tense."
    },
    {
        question: "We haven't decided where to go ______.",
        options: ["already", "just", "yet", "never"],
        answer: 2,
        explanation: "Kalimat negatif (haven't decided) membutuhkan 'yet' di akhir."
    },
    {
        question: "Have you ______ seen a ghost?",
        options: ["ever", "never", "yet", "since"],
        answer: 0,
        explanation: "Dalam pertanyaan pengalaman, kita menggunakan 'ever' (pernah) di antara subjek dan V3."
    },
    {
        question: "I have ______ the email. You can check it now.",
        options: ["send", "sent", "sending", "sended"],
        answer: 1,
        explanation: "V3 dari 'send' adalah 'sent'. 'Sended' tidak baku."
    },
    {
        question: "Nobody ______ come to the shop today.",
        options: ["have", "has", "is", "was"],
        answer: 1,
        explanation: "Kata ganti tak tentu (Indefinite Pronoun) seperti 'Nobody', 'Someone', 'Everybody' dianggap tunggal (singular). Maka pakai 'has'."
    },
    {
        question: "She has been in the hospital ______ Monday.",
        options: ["for", "since", "during", "at"],
        answer: 1,
        explanation: "'Monday' adalah nama hari (titik waktu), jadi gunakan 'since'."
    },
    {
        question: "I have ______ done my homework. Can I play now?",
        options: ["yet", "already", "since", "ever"],
        answer: 1,
        explanation: "Menyatakan pekerjaan sudah selesai dilakukan. 'Already' menekankan penyelesaian."
    },

    // --- LEVEL: EXPERT (10 Soal) ---
    // Fokus: Perbedaan 'Gone' vs 'Been', Present Perfect vs Past Simple, dan nuansa makna/konteks kompleks.

    {
        question: "Where is Mom? She has ______ to the supermarket.",
        options: ["been", "gone", "went", "going"],
        answer: 1,
        explanation: "Perbedaan 'Gone' vs 'Been'. 'Gone' artinya pergi dan belum kembali (masih di sana). Karena ditanya 'Where is Mom?', berarti dia tidak ada di sini, jadi jawabannya 'gone'."
    },
    {
        question: "I have ______ to Paris three times in my life.",
        options: ["been", "gone", "was", "go"],
        answer: 0,
        explanation: "'Been' digunakan untuk pengalaman pergi dan sudah kembali (sudah pernah ke sana). Karena pembicara ada di sini menceritakan pengalaman, gunakan 'been'."
    },
    {
        question: "Ouch! I ______ my finger.",
        options: ["cut", "have cut", "had cut", "cutting"],
        answer: 1,
        explanation: "Kejadian baru saja terjadi dan efeknya terasa sekarang (sakit/berdarah). Present Perfect 'have cut' lebih tepat daripada Past Simple untuk menekankan hasil saat ini."
    },
    {
        question: "Shakespeare ______ many plays.",
        options: ["has written", "wrote", "had written", "has wrote"],
        answer: 1,
        explanation: "Pengecoh! Shakespeare sudah meninggal. Aksi hidupnya tidak berhubungan dengan masa kini (not connected to present). Gunakan Past Simple 'wrote', bukan Present Perfect."
    },
    {
        question: "My key is missing. I ______ it anywhere.",
        options: ["didn't find", "haven't found", "haven't been finding", "found"],
        answer: 1,
        explanation: "Kunci hilang sekarang. Fokusnya adalah hasil pencarian sampai detik ini (present result). 'Haven't found' (belum menemukannya) menjelaskan status kunci saat ini."
    },
    {
        question: "This is the best book I ______.",
        options: ["have ever read", "ever read", "had ever read", "am reading"],
        answer: 0,
        explanation: "Pola Superlatif: 'It is the [best/worst] ... I have ever [V3]'. Ini menghubungkan pengalaman masa lalu dengan penilaian saat ini."
    },
    {
        question: "When ______ you ______ to London?",
        options: ["have / moved", "did / move", "has / moved", "do / move"],
        answer: 1,
        explanation: "Kata tanya 'When' (kapan) meminta waktu spesifik di masa lampau. Present Perfect TIDAK BOLEH digunakan dengan waktu spesifik. Gunakan Past Simple: 'Did you move'."
    },
    {
        question: "The government ______ taxes again.",
        options: ["have raised", "has raised", "raise", "raised"],
        answer: 1,
        explanation: "Collective Noun 'The government' bisa dianggap tunggal (unit) atau jamak (orang-orangnya). Secara umum/formal dianggap tunggal: 'has raised'. Fokus pada pengumuman/berita baru."
    },
    {
        question: "I can't get in because I ______ my keys.",
        options: ["lost", "have lost", "lose", "losing"],
        answer: 1,
        explanation: "Alasan tidak bisa masuk SEKARANG adalah karena kunci hilang. Present Perfect 'have lost' menekankan konsekuensi di masa kini."
    },
    {
        question: "How long ______ you ______ your best friend?",
        options: ["did / know", "have / known", "do / know", "are / knowing"],
        answer: 1,
        explanation: "Pertanyaan 'How long' (berapa lama) untuk hubungan yang masih terjalin sampai sekarang harus menggunakan Present Perfect. Ingat 'know' adalah stative verb, tidak boleh 'have been knowing'."
    }
];