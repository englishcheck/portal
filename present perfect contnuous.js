const questionsSource = [
    // --- LEVEL: BEGINNER (20 Soal) ---
    // Fokus: Struktur dasar (S + have/has + been + V-ing) dan Subject-Verb Agreement.

    {
        question: "I ______ waiting for you since 8 o'clock.",
        options: ["have been", "has been", "am", "was"],
        answer: 0,
        explanation: "Subject 'I' menggunakan auxiliary 'have'. Rumus Present Perfect Continuous adalah 'have been + V-ing'."
    },
    {
        question: "She ______ working on her project for two hours.",
        options: ["have been", "has been", "is", "were"],
        answer: 1,
        explanation: "Subject tunggal (singular) 'She' harus menggunakan auxiliary 'has'. Jadi, 'has been'."
    },
    {
        question: "They ______ football in the park all afternoon.",
        options: ["has been playing", "have been playing", "are playing", "played"],
        answer: 1,
        explanation: "Subject jamak (plural) 'They' menggunakan 'have'. Struktur lengkapnya: have + been + playing."
    },
    {
        question: "We ______ here for more than ten years.",
        options: ["has been living", "have been living", "are living", "live"],
        answer: 1,
        explanation: "Subject 'We' adalah jamak, jadi menggunakan 'have'. Penanda waktu 'for more than ten years' menunjukkan durasi yang masih berlangsung."
    },
    {
        question: "It ______ raining since last night.",
        options: ["have been", "has been", "is", "was"],
        answer: 1,
        explanation: "Subject 'It' (singular/non-human) menggunakan 'has'. Polanya: has + been + V-ing (raining)."
    },
    {
        question: "You ______ sleeping all day, wake up!",
        options: ["has been", "have been", "are", "were"],
        answer: 1,
        explanation: "Subject 'You' selalu dipasangkan dengan auxiliary 'have', meskipun merujuk pada satu orang."
    },
    {
        question: "The baby ______ crying for 30 minutes.",
        options: ["have been", "has been", "is", "are"],
        answer: 1,
        explanation: "Subject 'The baby' adalah tunggal (singular noun), setara dengan he/she/it, maka menggunakan 'has been'."
    },
    {
        question: "My parents ______ travelling around Europe this month.",
        options: ["has been", "have been", "are", "do"],
        answer: 1,
        explanation: "Subject 'My parents' adalah jamak (plural), setara dengan 'they', maka menggunakan 'have been'."
    },
    {
        question: "He ______ English at that course since 2020.",
        options: ["has been studying", "have been studying", "is studying", "studies"],
        answer: 0,
        explanation: "Subject 'He' membutuhkan 'has'. Struktur kalimat memerlukan V-ing (studying) setelah 'been'."
    },
    {
        question: "______ you been waiting long?",
        options: ["Has", "Have", "Are", "Did"],
        answer: 1,
        explanation: "Kalimat tanya (Interrogative). Auxiliary diletakkan di depan. Karena subjectnya 'you', maka gunakan 'Have'."
    },
    {
        question: "John has ______ painting the wall.",
        options: ["been", "be", "being", "is"],
        answer: 0,
        explanation: "Dalam struktur Perfect Continuous, setelah have/has wajib diikuti oleh 'been' (V3 dari be)."
    },
    {
        question: "We have been ______ this movie for an hour.",
        options: ["watch", "watched", "watching", "watches"],
        answer: 2,
        explanation: "Setelah 'have been', kata kerja utama harus dalam bentuk Present Participle (V-ing)."
    },
    {
        question: "______ she been cooking dinner?",
        options: ["Have", "Has", "Is", "Does"],
        answer: 1,
        explanation: "Kalimat tanya dengan subject 'she' dimulai dengan auxiliary 'Has'."
    },
    {
        question: "I ______ feeling well lately.",
        options: ["haven't been", "hasn't been", "am not", "don't"],
        answer: 0,
        explanation: "Kalimat negatif. Subject 'I' menggunakan 'have', ditambah 'not' menjadi 'haven't'. Struktur: haven't + been + V-ing."
    },
    {
        question: "The dog ______ barking at the stranger.",
        options: ["have been", "has been", "is", "were"],
        answer: 1,
        explanation: "Subject 'The dog' tunggal, menggunakan 'has been'."
    },
    {
        question: "My sister has been ______ the piano.",
        options: ["practice", "practiced", "practicing", "practices"],
        answer: 2,
        explanation: "Kata kerja harus berakhiran -ing (practicing) karena ada 'has been'."
    },
    {
        question: "How long ______ they been playing?",
        options: ["has", "have", "are", "do"],
        answer: 1,
        explanation: "Pertanyaan 'Wh-question'. Subject 'they' menentukan penggunaan auxiliary 'have'."
    },
    {
        question: "Tom and Jerry ______ fighting again.",
        options: ["has been", "have been", "is", "was"],
        answer: 1,
        explanation: "Subject 'Tom and Jerry' adalah jamak (dua orang), jadi menggunakan 'have been'."
    },
    {
        question: "It has not ______ snowing here.",
        options: ["be", "being", "been", "bean"],
        answer: 2,
        explanation: "Bentuk negatif tetap membutuhkan 'been' setelah not. 'Has not been'."
    },
    {
        question: "They have been ______ to solve the problem.",
        options: ["try", "tried", "trying", "tries"],
        answer: 2,
        explanation: "Memerlukan V-ing (trying) untuk melengkapi rumus Present Perfect Continuous."
    },

    // --- LEVEL: INTERMEDIATE (15 Soal) ---
    // Fokus: Penggunaan 'For' vs 'Since', Indikasi waktu (Lately, Recently), dan Konteks Sebab-Akibat.

    {
        question: "I am tired because I ______ in the garden all day.",
        options: ["work", "have been working", "am working", "worked"],
        answer: 1,
        explanation: "Kalimat ini menunjukkan hubungan sebab-akibat. Efek sekarang (tired) disebabkan oleh aktivitas durasi (all day) yang baru saja selesai atau masih berlangsung."
    },
    {
        question: "She has been living here ______ 2015.",
        options: ["for", "since", "in", "during"],
        answer: 1,
        explanation: "Grammar: Gunakan 'since' untuk titik awal waktu (starting point) seperti tahun, bulan, atau jam spesifik."
    },
    {
        question: "We have been waiting for the train ______ two hours.",
        options: ["since", "for", "at", "by"],
        answer: 1,
        explanation: "Grammar: Gunakan 'for' untuk menyatakan durasi atau rentang waktu (a period of time)."
    },
    {
        question: "Your eyes are red. ______ you ______ crying?",
        options: ["Have / been", "Has / been", "Are / crying", "Did / cry"],
        answer: 0,
        explanation: "Bukti fisik sekarang (red eyes) mengindikasikan aktivitas yang baru saja terjadi. Gunakan pola tanya: Have + S + been + V-ing."
    },
    {
        question: "He ______ to call you all morning.",
        options: ["has tried", "has been trying", "tried", "is trying"],
        answer: 1,
        explanation: "Penanda waktu 'all morning' menekankan durasi dan usaha yang berulang-ulang, sehingga Present Perfect Continuous lebih tepat daripada Present Perfect Simple."
    },
    {
        question: "The road is wet. It ______ raining.",
        options: ["has been", "is", "was", "had been"],
        answer: 0,
        explanation: "Kita melihat hasil saat ini (wet road) dari aktivitas lampau yang baru saja berhenti. Grammar: It + has + been + V-ing (tersirat)."
    },
    {
        question: "I ______ this book for weeks, but I haven't finished it yet.",
        options: ["read", "am reading", "have been reading", "have read"],
        answer: 2,
        explanation: "Menekankan proses yang berlangsung lama (for weeks) dan belum selesai. Jika sudah selesai, kita menggunakan 'have read'."
    },
    {
        question: "They ______ a lot of noise lately.",
        options: ["are making", "have been making", "made", "make"],
        answer: 1,
        explanation: "Kata keterangan 'lately' (akhir-akhir ini) adalah sinyal kuat untuk Present Perfect Continuous, menunjukkan kebiasaan berulang baru-baru ini."
    },
    {
        question: "How long ______ you ______ English?",
        options: ["do / learn", "are / learning", "have / been learning", "did / learn"],
        answer: 2,
        explanation: "Pertanyaan 'How long' menanyakan durasi dari masa lalu hingga sekarang, wajib menggunakan Perfect Continuous."
    },
    {
        question: "My phone ______ ringing for five minutes. Who is it?",
        options: ["is", "was", "has been", "had been"],
        answer: 2,
        explanation: "Aksi dimulai 5 menit lalu dan MASIH berlangsung sekarang. Gunakan 'has been'."
    },
    {
        question: "She ______ gym classes since she moved here.",
        options: ["has been taking", "is taking", "took", "has taken"],
        answer: 0,
        explanation: "Ada 'since' + klausa lampau. Main clause harus dalam bentuk Present Perfect (Continuous) untuk menunjukkan aktivitas rutin sejak saat itu hingga kini."
    },
    {
        question: "The children are dirty because they ______ in the mud.",
        options: ["played", "have been playing", "are playing", "play"],
        answer: 1,
        explanation: "Penjelasan sebab (kotor) akibat aktivitas yang baru saja dilakukan (main lumpur). Continuous menekankan aktivitasnya."
    },
    {
        question: "I ______ about buying a new car recently.",
        options: ["thought", "have thought", "have been thinking", "am thinking"],
        answer: 2,
        explanation: "'Think' di sini bermakna 'mempertimbangkan' (mental process), bukan pendapat statis. Dengan 'recently', bentuk continuous lebih tepat."
    },
    {
        question: "Someone ______ my cookies! There are only a few left.",
        options: ["has eaten", "has been eating", "eats", "ate"],
        answer: 1,
        explanation: "Fokus pada aktivitas yang 'mengurangi' jumlah kue (incomplete action) atau bukti remah-remah. Jika kue habis total, biasanya 'has eaten'."
    },
    {
        question: "Sorry I'm late. ______ you ______ long?",
        options: ["Have / wait", "Do / wait", "Have / been waiting", "Are / waiting"],
        answer: 2,
        explanation: "Menanyakan durasi menunggu hingga saat pembicara tiba."
    },

    // --- LEVEL: EXPERT (15 Soal) ---
    // Fokus: Stative Verbs (Pengecualian), Perbedaan dengan Present Perfect Simple (Quantity vs Duration), dan Nuansa Permanen vs Sementara.

    {
        question: "I ______ him for ten years.",
        options: ["have been knowing", "have known", "know", "am knowing"],
        answer: 1,
        explanation: "Jebakan Stative Verb! Kata kerja 'Know' adalah stative verb (kata kerja keadaan) yang TIDAK boleh dalam bentuk continuous (-ing). Gunakan Present Perfect Simple."
    },
    {
        question: "She ______ three letters this morning.",
        options: ["has been writing", "has written", "writes", "is writing"],
        answer: 1,
        explanation: "Fokus pada KUANTITAS/HASIL (three letters). Jika menyebutkan jumlah hasil, gunakan Present Perfect Simple. Continuous digunakan jika fokus pada durasi tanpa menyebut jumlah."
    },
    {
        question: "He ______ the car, so it looks new again.",
        options: ["has been washing", "has washed", "washes", "is washing"],
        answer: 1,
        explanation: "Fokus pada HASIL AKHIR (looks new). Aksi pencucian sudah SELESAI. Jika menggunakan 'has been washing', fokusnya pada kegiatan mencucinya, bukan bersihnya mobil."
    },
    {
        question: "We ______ to understand this theory for hours.",
        options: ["have been wanting", "have wanted", "are wanting", "want"],
        answer: 1,
        explanation: "Jebakan Stative Verb! 'Want' adalah kata kerja perasaan/keinginan yang tidak umum digunakan dalam bentuk continuous."
    },
    {
        question: "I ______ here for a month, but I plan to move soon.",
        options: ["live", "have lived", "have been living", "lived"],
        answer: 2,
        explanation: "Nuansa: 'Have been living' menyiratkan situasi SEMENTARA (temporary). Jika permanen, 'have lived' lebih umum, meskipun keduanya bisa benar secara gramatikal. Di sini konteks 'move soon' mendukung continuous."
    },
    {
        question: "The car belongs to me. I ______ it for years.",
        options: ["have been owning", "have owned", "am owning", "owned"],
        answer: 1,
        explanation: "Stative Verb Rule: 'Own' (memiliki) tidak bisa dalam bentuk continuous. Gunakan 'have owned'."
    },
    {
        question: "Where have you been? I ______ for you everywhere!",
        options: ["have looked", "have been looking", "look", "looked"],
        answer: 1,
        explanation: "Menekankan proses pencarian yang intens dan berdurasi. 'Have been looking' lebih tepat untuk menunjukkan kekesalan atau usaha panjang."
    },
    {
        question: "They ______ the house all summer and it's still not finished.",
        options: ["have painted", "have been painting", "paint", "are painting"],
        answer: 1,
        explanation: "Aktivitas belum selesai (incomplete) meskipun sudah berlangsung lama. Continuous menekankan prosesnya. Jika 'have painted', artinya sudah selesai dicat."
    },
    {
        question: "I ______ the news regularly lately.",
        options: ["have been watching", "have watched", "am watching", "watch"],
        answer: 0,
        explanation: "Kebiasaan berulang (regularly) yang terjadi baru-baru ini (lately) paling tepat menggunakan Present Perfect Continuous."
    },
    {
        question: "He ______ to fix the TV, but he hasn't succeeded yet.",
        options: ["has tried", "has been trying", "tries", "tried"],
        answer: 1,
        explanation: "Aksi mencoba berulang kali dalam satu periode waktu dan belum berhasil. Continuous menekankan usaha yang terus menerus."
    },
    {
        question: "______ the cake? There is chocolate on your face.",
        options: ["Have you eaten", "Have you been eating", "Did you eat", "Do you eat"],
        answer: 1,
        explanation: "Beda nuansa: 'Have you eaten the cake?' (Apakah kue sudah habis?). 'Have you been eating?' (Apakah kamu barusan makan kue? - tidak peduli habis atau tidak, fokus pada jejak aktivitas)."
    },
    {
        question: "We ______ to convince him, but he won't listen.",
        options: ["have been trying", "are trying", "tried", "have tried"],
        answer: 0,
        explanation: "Usaha yang dimulai di masa lalu dan masih berlanjut sampai saat bicara (persistence)."
    },
    {
        question: "She ______ anything since breakfast.",
        options: ["hasn't been eating", "hasn't eaten", "didn't eat", "doesn't eat"],
        answer: 1,
        explanation: "Negasi untuk aktivitas sesaat (makan). Biasanya jika menyangkut 'tidak melakukan apa-apa' hingga tuntas, kita pakai Simple Perfect ('hasn't eaten'). Continuous ('hasn't been eating') menyiratkan dia tidak sedang dalam proses makan terus menerus, yang terdengar aneh."
    },
    {
        question: "My neighbours ______ ! It is so annoying.",
        options: ["always argue", "have always argued", "have always been arguing", "are always arguing"],
        answer: 3,
        explanation: "Pengecualian Khusus (Expert): Untuk keluhan tentang kebiasaan yang mengganggu, seringkali digunakan 'are always V-ing' (Present Continuous). Namun jika konteksnya durasi panjang dari dulu sampai sekarang, 'have been arguing' bisa diterima, tapi opsi yang paling alami untuk 'annoying habit' seringkali Present Continuous dengan always. (Di soal ini, jika opsinya 'have been arguing' vs 'argued', pilih 'have been'. Tapi hati-hati dengan nuansa keluhan)."
    },
    {
        question: "I ______ well recently, so I went to the doctor.",
        options: ["haven't felt", "haven't been feeling", "don't feel", "didn't feel"],
        answer: 1,
        explanation: "Untuk kesehatan/perasaan fisik (feel) yang berlangsung dalam periode dekat (recently), Continuous sangat umum digunakan untuk menekankan kondisi yang sedang dialami."
    }
];