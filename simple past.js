const questionsSource = [
    // --- LEVEL: BEGINNER (20 Soal) ---
    // Fokus: Regular Verbs (-ed), Common Irregular Verbs, Basic To Be (Was/Were)

    {
        question: "I ______ my grandmother last weekend.",
        options: ["visit", "visited", "visiting", "visits"],
        answer: 1,
        explanation: "Kata kerja 'visit' adalah regular verb. Dalam Simple Past Tense, kita menambahkan akhiran '-ed' menjadi 'visited'. Keterangan waktu 'last weekend' menunjukkan masa lampau."
    },
    {
        question: "She ______ to the cinema yesterday.",
        options: ["go", "goes", "went", "gone"],
        answer: 2,
        explanation: "Kata kerja 'go' adalah irregular verb. Bentuk lampau (V2) dari 'go' adalah 'went'."
    },
    {
        question: "They ______ football in the park yesterday afternoon.",
        options: ["play", "played", "playing", "plays"],
        answer: 1,
        explanation: "'Play' adalah regular verb. Bentuk lampaunya adalah 'played'."
    },
    {
        question: "We ______ very happy about the news.",
        options: ["was", "were", "are", "is"],
        answer: 1,
        explanation: "Subjek 'We' (jamak) menggunakan to be lampau 'were'. ('Was' untuk I/He/She/It; 'Were' untuk You/We/They)."
    },
    {
        question: "He ______ hungry, so he ate a sandwich.",
        options: ["was", "were", "is", "be"],
        answer: 0,
        explanation: "Subjek 'He' (tunggal) menggunakan to be lampau 'was'."
    },
    {
        question: "I ______ a new phone last week.",
        options: ["buy", "buyed", "bought", "buying"],
        answer: 2,
        explanation: "'Buy' adalah irregular verb. Bentuk V2-nya adalah 'bought', bukan 'buyed'."
    },
    {
        question: "She ______ hard for the exam.",
        options: ["study", "studied", "studying", "studies"],
        answer: 1,
        explanation: "Untuk kata kerja berakhiran konsonan + y (study), 'y' berubah menjadi 'i' lalu ditambah '-ed'. Jadi 'studied'."
    },
    {
        question: "The rain ______ an hour ago.",
        options: ["stop", "stopped", "stoped", "stopping"],
        answer: 1,
        explanation: "Aturan ejaan: Untuk kata satu suku kata berakhiran konsonan-vokal-konsonan (stop), huruf terakhir digandakan sebelum '-ed'. Jadi 'stopped'."
    },
    {
        question: "We ______ pizza for dinner last night.",
        options: ["eat", "ate", "eaten", "eating"],
        answer: 1,
        explanation: "'Eat' adalah irregular verb. Bentuk lampaunya (V2) adalah 'ate'."
    },
    {
        question: "They ______ a sad movie.",
        options: ["watch", "watched", "watching", "watches"],
        answer: 1,
        explanation: "'Watch' adalah regular verb, cukup tambahkan '-ed' menjadi 'watched'."
    },
    {
        question: "It ______ heavily last night.",
        options: ["rain", "rained", "raining", "rains"],
        answer: 1,
        explanation: "'Rain' adalah regular verb. Bentuk lampaunya adalah 'rained'."
    },
    {
        question: "You ______ late for class yesterday.",
        options: ["was", "were", "are", "is"],
        answer: 1,
        explanation: "Subjek 'You' selalu berpasangan dengan to be 'were' dalam bentuk lampau."
    },
    {
        question: "The bird ______ away when I came closer.",
        options: ["fly", "flied", "flew", "flown"],
        answer: 2,
        explanation: "'Fly' adalah irregular verb. Bentuk V2-nya adalah 'flew'."
    },
    {
        question: "My father ______ his car this morning.",
        options: ["wash", "washed", "washing", "washes"],
        answer: 1,
        explanation: "'Wash' adalah regular verb. Tambahkan '-ed' menjadi 'washed'."
    },
    {
        question: "We ______ a beautiful song together.",
        options: ["sing", "sang", "sung", "singing"],
        answer: 1,
        explanation: "'Sing' adalah irregular verb. Bentuk V2-nya adalah 'sang'. (Sing - Sang - Sung)."
    },
    {
        question: "He ______ me a letter.",
        options: ["write", "wrote", "written", "writing"],
        answer: 1,
        explanation: "'Write' adalah irregular verb. Bentuk V2-nya adalah 'wrote'."
    },
    {
        question: "I ______ a lot of water after the exercise.",
        options: ["drink", "drank", "drunk", "drinking"],
        answer: 1,
        explanation: "'Drink' adalah irregular verb. Bentuk V2-nya adalah 'drank'. (Drink - Drank - Drunk)."
    },
    {
        question: "She ______ her keys on the table.",
        options: ["leave", "left", "leaved", "leaving"],
        answer: 1,
        explanation: "'Leave' adalah irregular verb. Bentuk V2-nya adalah 'left'."
    },
    {
        question: "The baby ______ all night.",
        options: ["cry", "cryed", "cried", "crying"],
        answer: 2,
        explanation: "Seperti 'study', kata 'cry' berakhiran 'y' didahului konsonan. Ubah 'y' menjadi 'i' + 'ed' -> 'cried'."
    },
    {
        question: "Tom ______ to the party alone.",
        options: ["come", "came", "coming", "comes"],
        answer: 1,
        explanation: "'Come' adalah irregular verb. Bentuk V2-nya adalah 'came'."
    },

    // --- LEVEL: INTERMEDIATE (20 Soal) ---
    // Fokus: Kalimat Negatif, Interrogative (Did), Time Signals, dan Irregular Verbs lanjutan.

    {
        question: "I ______ enjoy the movie yesterday.",
        options: ["didn't", "don't", "wasn't", "not"],
        answer: 0,
        explanation: "Untuk membentuk kalimat negatif verbal di Simple Past, gunakan auxiliary 'did not' (didn't) diikuti Verb 1."
    },
    {
        question: "______ you see the accident?",
        options: ["Do", "Did", "Was", "Were"],
        answer: 1,
        explanation: "Kalimat tanya verbal (menggunakan kata kerja 'see') di masa lampau menggunakan auxiliary 'Did' di awal kalimat."
    },
    {
        question: "She didn't ______ the answer.",
        options: ["knew", "know", "known", "knows"],
        answer: 1,
        explanation: "Setelah auxiliary 'didn't', kata kerja harus KEMBALI ke bentuk dasar (Verb 1), yaitu 'know', bukan 'knew'."
    },
    {
        question: "Where ______ you go for your holiday?",
        options: ["did", "do", "were", "was"],
        answer: 0,
        explanation: "Wh-question dengan kata kerja aksi ('go') menggunakan pola: Wh + did + Subject + V1."
    },
    {
        question: "We ______ not at home when you called.",
        options: ["did", "was", "were", "are"],
        answer: 2,
        explanation: "Ini adalah kalimat nominal (tanpa kata kerja aksi). Subjek 'We' menggunakan to be 'were'. Negatifnya 'were not'."
    },
    {
        question: "I ______ my homework two hours ago.",
        options: ["finish", "finished", "finishing", "have finished"],
        answer: 1,
        explanation: "Keterangan waktu 'ago' (two hours ago) adalah penanda mutlak Simple Past Tense. Gunakan V2 'finished'."
    },
    {
        question: "They ______ bring the camera.",
        options: ["weren't", "didn't", "not", "don't"],
        answer: 1,
        explanation: "Ada kata kerja 'bring', maka kalimat negatifnya harus menggunakan 'didn't'."
    },
    {
        question: "The teacher ______ us a difficult question.",
        options: ["teach", "taught", "teached", "teaching"],
        answer: 1,
        explanation: "'Teach' adalah irregular verb. Bentuk V2-nya adalah 'taught'."
    },
    {
        question: "I ______ the bus so I had to walk.",
        options: ["miss", "missed", "missing", "misses"],
        answer: 1,
        explanation: "Konteks sebab-akibat di masa lampau (had to walk). Penyebabnya juga bentuk lampau: 'missed'."
    },
    {
        question: "He ______ his leg while playing soccer.",
        options: ["break", "broke", "broken", "breaking"],
        answer: 1,
        explanation: "'Break' adalah irregular verb. Bentuk V2-nya adalah 'broke'."
    },
    {
        question: "______ she happy with the result?",
        options: ["Did", "Was", "Were", "Does"],
        answer: 1,
        explanation: "Kalimat ini menanyakan perasaan (adjective 'happy'), bukan aksi. Gunakan To Be. Subjek 'She' pasangannya 'Was'."
    },
    {
        question: "I ______ that you were busy.",
        options: ["think", "thought", "thinked", "thinking"],
        answer: 1,
        explanation: "'Think' adalah irregular verb. Bentuk V2-nya adalah 'thought'."
    },
    {
        question: "We ______ to bring the map.",
        options: ["forget", "forgot", "forgotten", "forgetting"],
        answer: 1,
        explanation: "'Forget' adalah irregular verb. Bentuk V2-nya adalah 'forgot'."
    },
    {
        question: "Who ______ this delicious cake?",
        options: ["make", "made", "maked", "making"],
        answer: 1,
        explanation: "'Make' adalah irregular verb. Bentuk V2-nya adalah 'made'. Pertanyaan 'Who' sebagai subjek langsung diikuti V2."
    },
    {
        question: "I ______ sleep well last night.",
        options: ["don't", "wasn't", "didn't", "not"],
        answer: 2,
        explanation: "Negatif lampau untuk kata kerja 'sleep' menggunakan 'didn't'. 'I didn't sleep'."
    },
    {
        question: "She ______ a beautiful dress to the party.",
        options: ["wear", "wore", "worn", "wearing"],
        answer: 1,
        explanation: "'Wear' adalah irregular verb. Bentuk V2-nya adalah 'wore'."
    },
    {
        question: "They ______ the house in 2010.",
        options: ["build", "built", "builded", "building"],
        answer: 1,
        explanation: "Keterangan waktu spesifik di masa lalu (in 2010). 'Build' adalah irregular verb, V2-nya 'built' (dengan 't')."
    },
    {
        question: "______ you find what you were looking for?",
        options: ["Did", "Do", "Were", "Have"],
        answer: 0,
        explanation: "Pertanyaan dengan kata kerja dasar 'find' membutuhkan 'Did'."
    },
    {
        question: "The police ______ the thief.",
        options: ["catch", "catched", "caught", "catching"],
        answer: 2,
        explanation: "'Catch' adalah irregular verb. Bentuk V2-nya adalah 'caught'."
    },
    {
        question: "My brother ______ home very late yesterday.",
        options: ["get", "got", "gotten", "getting"],
        answer: 1,
        explanation: "'Get' adalah irregular verb. Bentuk V2-nya adalah 'got'."
    },

    // --- LEVEL: EXPERT (10 Soal) ---
    // Fokus: Tricky Irregular Verbs (Same forms, Lay/Lie), Passive Context (Was + V3), & Nuance.

    {
        question: "I ______ my finger while cutting onions.",
        options: ["cut", "cuted", "cutting", "cuts"],
        answer: 0,
        explanation: "'Cut' adalah irregular verb spesial dimana V1, V2, dan V3 bentuknya SAMA. Jadi bentuk lampaunya tetap 'cut'."
    },
    {
        question: "She ______ the book on the table.",
        options: ["put", "putted", "pat", "putting"],
        answer: 0,
        explanation: "Sama seperti 'cut', kata kerja 'put' bentuk lampaunya (V2) tetap 'put'."
    },
    {
        question: "The new car ______ a fortune.",
        options: ["cost", "costed", "costing", "casts"],
        answer: 0,
        explanation: "'Cost' (berharga/memakan biaya) adalah verb dimana V1, V2, V3 sama. Jadi 'The car cost (V2) a fortune'."
    },
    {
        question: "He ______ the heavy box on the floor.",
        options: ["lie", "lay", "laid", "lain"],
        answer: 2,
        explanation: "Perbedaan 'Lie' vs 'Lay'. 'Lay' (meletakkan objek) adalah transitif. V2 dari 'Lay' adalah 'Laid'. Sedangkan V2 dari 'Lie' (berbaring) adalah 'Lay'."
    },
    {
        question: "After lunch, I ______ down on the sofa for a nap.",
        options: ["lay", "laid", "lie", "lied"],
        answer: 0,
        explanation: "Disini maknanya 'berbaring' (intransitif, tanpa objek). V1 Lie -> V2 Lay. Jawabannya 'lay'."
    },
    {
        question: "Yesterday, I ______ the news in the newspaper.",
        options: ["read", "readed", "red", "reading"],
        answer: 0,
        explanation: "Tulisan V1 dan V2 dari 'read' sama persis, tapi cara bacanya beda (V1 /riːd/, V2 /red/). Jawabannya tetap ditulis 'read'."
    },
    {
        question: "The sun ______ at 6 AM this morning.",
        options: ["raise", "rose", "raised", "rise"],
        answer: 1,
        explanation: "Perbedaan 'Rise' (terbit/naik sendiri) vs 'Raise' (menaikkan sesuatu). Matahari terbit sendiri, jadi pakai 'Rise'. V2 dari Rise adalah 'Rose'."
    },
    {
        question: "When I was a child, I ______ to be an astronaut.",
        options: ["want", "wanted", "wanting", "wants"],
        answer: 1,
        explanation: "Konteks 'When I was a child' memaksa penggunaan Simple Past untuk fakta di masa lalu yang sudah tidak terjadi lagi/berubah. 'Wanted'."
    },
    {
        question: "The thief ______ from the police.",
        options: ["flee", "fled", "fleed", "flown"],
        answer: 1,
        explanation: "'Flee' (melarikan diri) adalah irregular verb. V2-nya adalah 'fled'."
    },
    {
        question: "She ______ the ball to me.",
        options: ["throw", "threw", "thrown", "throwed"],
        answer: 1,
        explanation: "'Throw' adalah irregular verb. Bentuk V2-nya adalah 'threw' (seperti blow-blew, grow-grew)."
    }
];