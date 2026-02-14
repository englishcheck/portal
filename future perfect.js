const questionsSource = [
    // --- TO BE (AM, IS, ARE) ---
    {
        question: "By tomorrow morning, I ______ my homework.",
        options: ["will finished", "will have finished", "have finished", "will finishing"],
        answer: 1,
        explanation: "Rumus Future Perfect adalah 'S + will have + Verb 3'. Di sini, 'finished' adalah V3 yang tepat setelah 'will have'. Pilihan lain salah secara gramatikal."
    },
    {
        question: "She ______ the email by the time you ask her.",
        options: ["will has sent", "will have sent", "will sent", "sending"],
        answer: 1,
        explanation: "Meskipun subjeknya 'She' (singular), dalam Future Perfect kita selalu menggunakan auxiliary 'have', bukan 'has'. Jadi, 'will have sent' adalah jawaban yang benar."
    },
    {
        question: "They ______ Paris by next week.",
        options: ["will have left", "will left", "have leaving", "will have leave"],
        answer: 0,
        explanation: "Kata kerja bentuk ketiga (V3) dari 'leave' adalah 'left'. Polanya adalah 'will have + left'."
    },
    {
        question: "By 8 PM tonight, we ______ dinner.",
        options: ["will have eat", "will have ate", "will have eaten", "will eating"],
        answer: 2,
        explanation: "V3 dari 'eat' adalah 'eaten'. 'Ate' adalah V2, dan 'eat' adalah V1. Future Perfect wajib menggunakan V3."
    },
    {
        question: "John ______ from the university by next year.",
        options: ["will have graduated", "will graduated", "has graduated", "will have graduate"],
        answer: 0,
        explanation: "Tanda waktu 'by next year' mengindikasikan aksi yang akan tuntas di masa depan. Gunakan 'will have' + 'graduated' (regular verb)."
    },
    {
        question: "The movie ______ by the time we arrive at the cinema.",
        options: ["will have start", "will has started", "will have started", "started"],
        answer: 2,
        explanation: "Subjek 'The movie' tunggal, tapi tetap pakai 'will have'. V3 dari 'start' adalah 'started'."
    },
    {
        question: "I ______ the book by Sunday.",
        options: ["will have read", "will have red", "will read", "have read"],
        answer: 0,
        explanation: "V3 dari 'read' tulisannya tetap 'read' (dibaca /red/). Jadi 'will have read' adalah bentuk yang tepat."
    },
    {
        question: "You ______ enough money by the end of the month.",
        options: ["will saved", "will have save", "will have saved", "will be save"],
        answer: 2,
        explanation: "Membutuhkan 'will have' + V3. 'Saved' adalah bentuk V3 dari 'save'."
    },
    {
        question: "He ______ the car before his dad comes home.",
        options: ["will have washed", "will washing", "will have wash", "has washed"],
        answer: 0,
        explanation: "Pola Future Perfect: 'will have' + 'washed' (V3). Aksi mencuci mobil akan selesai sebelum aksi lain (ayah pulang) terjadi."
    },
    {
        question: "By next summer, they ______ a new house.",
        options: ["will have build", "will have built", "will build", "built"],
        answer: 1,
        explanation: "V3 dari 'build' adalah 'built' (dengan t). 'Build' (dengan d) adalah V1."
    },
    {
        question: "Mom ______ cooking by the time we get home.",
        options: ["will have stopped", "will has stopped", "will stopped", "stop"],
        answer: 0,
        explanation: "Gunakan 'will have' untuk semua subjek. 'Stopped' adalah V3 yang benar."
    },
    {
        question: "______ you ______ the task by 5 PM?",
        options: ["Will / have finished", "Do / have finished", "Have / will finished", "Will / finished"],
        answer: 0,
        explanation: "Ini adalah bentuk kalimat tanya (interrogative). Polanya: 'Will + Subject + have + V3?'. Jadi jawabannya 'Will... have finished'."
    },
    {
        question: "The sun ______ before we reach the beach.",
        options: ["will have set", "will has set", "will set", "set"],
        answer: 0,
        explanation: "V3 dari 'set' adalah 'set' (irregular verb yang bentuknya sama). Polanya 'will have set'."
    },
    {
        question: "I ______ to five different countries by the end of this year.",
        options: ["will have been", "will have be", "will be", "am being"],
        answer: 0,
        explanation: "Kita membutuhkan V3 dari 'be' untuk menyatakan 'telah berada/pergi ke'. V3 dari 'be' adalah 'been'."
    },
    {
        question: "The snow ______ by noon.",
        options: ["will have melted", "will melted", "will have melt", "is melting"],
        answer: 0,
        explanation: "Aksi (leleh) akan selesai pada waktu tertentu (noon). Gunakan 'will have' + 'melted' (V3)."
    },

    // 16-30 (Intermediate)
    {
        question: "By the time the police arrive, the thief ______.",
        options: ["will escape", "will have escaped", "has escaped", "escaped"],
        answer: 1,
        explanation: "Kombinasi klasik: 'By the time + Present Simple' (police arrive), pasangannya adalah Future Perfect (will have escaped) untuk aksi yang sudah tuntas duluan."
    },
    {
        question: "Don't worry, I ______ the report by the deadline.",
        options: ["won't have forget", "won't have forgotten", "not have forgotten", "won't forgotten"],
        answer: 1,
        explanation: "Bentuk negatif dari Future Perfect adalah 'will not have' atau 'won't have' + V3. V3 dari 'forget' adalah 'forgotten'."
    },
    {
        question: "By 2030, scientists ______ a cure for this disease.",
        options: ["will discovered", "will have discover", "will have discovered", "discover"],
        answer: 2,
        explanation: "Prediksi tentang penyelesaian suatu hal di masa depan (by 2030). Membutuhkan 'will have' + V3 'discovered'."
    },
    {
        question: "If we don't hurry, the train ______ before we reach the station.",
        options: ["will have left", "will leave", "left", "leaves"],
        answer: 0,
        explanation: "Kita berbicara tentang aksi yang 'sudah akan terjadi' (kereta berangkat) pada titik waktu tertentu di masa depan (sebelum kita sampai)."
    },
    {
        question: "I hope she ______ the news before she sees him.",
        options: ["will have heard", "will has heard", "will heard", "hear"],
        answer: 0,
        explanation: "Harapan tentang suatu aksi yang tuntas sebelum aksi lain. 'Heard' adalah V3 dari 'hear'. 'Will has' selalu salah."
    },
    {
        question: "By the end of his term, the President ______ the country for four years.",
        options: ["will have lead", "will have led", "will have leader", "will led"],
        answer: 1,
        explanation: "V3 dari 'lead' (memimpin) adalah 'led'. Jangan tertukar dengan logam timbal (lead) atau V1."
    },
    {
        question: "We can't meet at 9. I ______ my meeting by then.",
        options: ["won't have finish", "won't have finished", "won't finished", "not finish"],
        answer: 1,
        explanation: "Konteks: Alasan tidak bisa bertemu adalah karena rapat 'belum akan selesai'. Bentuk negatif: 'won't have finished'."
    },
    {
        question: "______ they ______ everything ready when the guests arrive?",
        options: ["Will / have got", "Will / has got", "Do / have got", "Are / having got"],
        answer: 0,
        explanation: "Kalimat tanya Future Perfect. 'Will' di depan, subjek 'they', lalu 'have got' (atau gotten). Pilihan 'Will / have got' paling tepat."
    },
    {
        question: "By the time you wake up, I ______ to work.",
        options: ["will have gone", "will have went", "will go", "have gone"],
        answer: 0,
        explanation: "V3 dari 'go' adalah 'gone'. 'Went' adalah V2 dan tidak boleh digunakan setelah 'have'."
    },
    {
        question: "Call me at 2 PM. The meeting ______ by then.",
        options: ["will have ended", "will ended", "ends", "has ended"],
        answer: 0,
        explanation: "Pada jam 2 siang (masa depan), rapat tersebut diprediksi sudah selesai. Gunakan 'will have ended'."
    },
    {
        question: "By next month, we ______ in this city for ten years.",
        options: ["will have lived", "will lived", "live", "have lived"],
        answer: 0,
        explanation: "Menyatakan durasi waktu yang akan tercapai di masa depan (for ten years). Ini ciri khas Future Perfect (atau Future Perfect Continuous)."
    },
    {
        question: "I'm sure he ______ the mistake by now.",
        options: ["will have realized", "will realized", "will has realized", "realizes"],
        answer: 0,
        explanation: "Future Perfect juga bisa digunakan untuk membuat asumsi tentang apa yang 'sudah terjadi' saat ini (by now), dilihat dari perspektif masa depan/prediksi."
    },
    {
        question: "The flowers ______ by the time you return from your trip.",
        options: ["will have bloomed", "will bloomed", "bloom", "will have bloom"],
        answer: 0,
        explanation: "Aksi mekar (bloom) akan tuntas sebelum kamu kembali. V3 dari 'bloom' adalah 'bloomed'."
    },
    {
        question: "______ you ______ the essay by Friday?",
        options: ["Will / have written", "Will / have wrote", "Will / wrote", "Do / write"],
        answer: 0,
        explanation: "Pertanyaan deadline. V3 dari 'write' adalah 'written', bukan 'wrote' (V2)."
    },
    {
        question: "They ______ the bridge before the rainy season starts.",
        options: ["will have completed", "will completed", "completed", "have complete"],
        answer: 0,
        explanation: "Target penyelesaian sebelum waktu tertentu (rainy season). Gunakan 'will have completed'."
    },

    // 31-45 (Expert)
    {
        question: "By next year, the new highway ______ by the construction team.",
        options: ["will have built", "will have been built", "will has been built", "will be built"],
        answer: 1,
        explanation: "Ini adalah Future Perfect Passive. Jalan raya (objek) 'akan telah DIBANGUN'. Rumus: S + will have been + V3. 'Will have been built' adalah jawaban benar."
    },
    {
        question: "Do you think the controversy ______ by the time the election is held?",
        options: ["will have been forgotten", "will have forgot", "will have been forgot", "will be forgotten"],
        answer: 0,
        explanation: "Kalimat Pasif: Kontroversi 'akan telah DILUPAKAN'. V3 dari forget adalah 'forgotten'. Jadi: 'will have been forgotten'."
    },
    {
        question: "Unless we act now, the opportunity ______ lost forever.",
        options: ["will have been", "will has been", "will be have", "will have"],
        answer: 0,
        explanation: "Disini kita butuh 'will have been' sebagai penghubung ke adjective/participle 'lost'. Artinya 'akan sudah menjadi hilang'."
    },
    {
        question: "By the time the CEO arrives, the proposal ______ by the board.",
        options: ["will have been reviewed", "will have reviewed", "will has reviewed", "will be review"],
        answer: 0,
        explanation: "Pasif: Proposal 'akan telah DITINJAU' (reviewed) oleh dewan. Membutuhkan 'been' di antara 'have' dan 'reviewed'."
    },
    {
        question: "Wait a bit longer. They ______ the decision yet.",
        options: ["won't have made", "won't have make", "won't made", "will not made"],
        answer: 0,
        explanation: "Pengecoh 'yet' biasanya untuk Present Perfect, tapi bisa dipakai di Future Perfect negatif untuk menekankan bahwa pada titik itu, keputusan BELUM dibuat. V3 'make' adalah 'made'."
    },
    {
        question: "I assume that by the time we get there, the best seats ______ taken.",
        options: ["will have been", "will have", "will be", "have been"],
        answer: 0,
        explanation: "Kursi-kursi 'akan telah DIAMBIL' (taken). Kalimat ini membutuhkan auxiliary pasif. 'Taken' sudah ada di soal (implisit atau eksplisit), kita butuh 'will have been'."
    },
    {
        question: "______ the project ______ by the deadline?",
        options: ["Will / have been completed", "Will / have completed", "Will / has been completed", "Has / will be completed"],
        answer: 0,
        explanation: "Pertanyaan Pasif: 'Akankah proyek tersebut TELAH DISELESAIKAN?'. Pola: Will + Subject + have been + V3."
    },
    {
        question: "By 2050, many species ______ extinct due to climate change.",
        options: ["will have become", "will have became", "will become", "will have been become"],
        answer: 0,
        explanation: "V3 dari 'become' adalah 'become' (kembali ke bentuk awal, V2-nya 'became'). Jadi 'will have become' adalah benar. Ini kalimat aktif (species menjadi punah)."
    },
    {
        question: "The documents ______ to the lawyer before the trial starts.",
        options: ["will have been sent", "will have sent", "will be sent", "will sent"],
        answer: 0,
        explanation: "Dokumen (benda mati) tidak bisa mengirim, jadi harus pasif (dikirim). 'Will have been sent'."
    },
    {
        question: "By the time you finish your degree, the curriculum ______ changed.",
        options: ["will have", "will has", "will is", "will was"],
        answer: 0,
        explanation: "Kalimat ini membutuhkan auxiliary untuk melengkapi 'changed' (V3). Kurikulum 'akan sudah berubah'. Jawabannya 'will have'."
    },
    {
        question: "Whatever happens, I ______ my best.",
        options: ["will have done", "will have do", "will have did", "will doing"],
        answer: 0,
        explanation: "Ungkapan 'I will have done my best' berarti pada akhirnya nanti, saya akan sudah melakukan yang terbaik (tidak ada penyesalan). V3 'do' adalah 'done'."
    },
    {
        question: "By the end of the century, fossil fuels ______ replaced by renewable energy.",
        options: ["will have been", "will have being", "will has been", "will be"],
        answer: 0,
        explanation: "Kalimat pasif: Bahan bakar fosil 'akan telah DIGANTIKAN' (replaced). Kita butuh 'will have been' sebelum kata 'replaced'."
    },
    {
        question: "She hopes that her novel ______ published by next winter.",
        options: ["will have been", "will have", "has been", "will be"],
        answer: 0,
        explanation: "Pasif: Novelnya 'akan telah DITERBITKAN' (published). Membutuhkan 'will have been'."
    },
    {
        question: "We predict that over a million tickets ______ sold by tomorrow.",
        options: ["will have been", "will have", "will be", "have been"],
        answer: 0,
        explanation: "Pasif: Tiket 'akan telah TERJUAL' (sold). Membutuhkan 'will have been'."
    },
    {
        question: "By the time he retires, he ______ at the company for 40 years.",
        options: ["will have worked", "will have work", "will worked", "worked"],
        answer: 0,
        explanation: "Kembali ke kalimat aktif namun dengan durasi panjang yang menekankan pencapaian waktu. 'Will have worked' (atau 'will have been working') adalah opsi yang paling tepat di sini."
    }
];