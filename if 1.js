const questionsSource = [
    // --- TO BE (AM, IS, ARE) ---
    {
        question: "If it ______ tomorrow, we will stay at home.",
        options: ["rains", "rain", "raining", "will rain"],
        answer: 0,
        explanation: "Pola Type 1: If + Simple Present. Subjek 'it' memerlukan verb dengan akhiran -s, jadi jawabannya 'rains'."
    },
    {
        question: "If you study hard, you ______ the exam.",
        options: ["pass", "passed", "will pass", "passing"],
        answer: 2,
        explanation: "Klausa 'If' sudah menggunakan Simple Present (study), maka klausa utama (result) harus menggunakan Future Tense (will + V1)."
    },
    {
        question: "She will cook dinner if he ______ the food.",
        options: ["buy", "buys", "buying", "bought"],
        answer: 1,
        explanation: "Klausa 'If' berada di belakang. Aturannya tetap: If + Simple Present. Subjek 'he' (tunggal) memerlukan verb+s ('buys')."
    },
    {
        question: "If I ______ time, I will help you.",
        options: ["have", "has", "had", "having"],
        answer: 0,
        explanation: "Subjek 'I' dalam Simple Present menggunakan 'have', bukan 'has'."
    },
    {
        question: "They ______ to the party if they are invited.",
        options: ["come", "comes", "will come", "came"],
        answer: 2,
        explanation: "Result clause membutuhkan Future Tense (will + verb). Jawabannya 'will come'."
    },
    {
        question: "If she ______ late, the teacher will be angry.",
        options: ["is", "am", "are", "be"],
        answer: 0,
        explanation: "Dalam Simple Present, 'to be' untuk subjek 'she' adalah 'is'."
    },
    {
        question: "If we ______ now, we will arrive on time.",
        options: ["leaves", "left", "leave", "leaving"],
        answer: 2,
        explanation: "Subjek 'we' (jamak) menggunakan verb dasar (V1) dalam Simple Present, yaitu 'leave'."
    },
    {
        question: "He ______ a new car if he gets the bonus.",
        options: ["buy", "will buy", "bought", "buys"],
        answer: 1,
        explanation: "Result clause untuk masa depan (future possibility) menggunakan 'will buy'."
    },
    {
        question: "If the bus ______, I will walk to school.",
        options: ["doesn't come", "don't come", "didn't come", "won't come"],
        answer: 0,
        explanation: "Kalimat negatif Simple Present untuk subjek tunggal 'the bus' (it) menggunakan 'doesn't'."
    },
    {
        question: "You will get sick if you ______ too much candy.",
        options: ["eats", "ate", "eat", "eaten"],
        answer: 2,
        explanation: "Subjek 'you' diikuti oleh verb dasar 'eat' tanpa tambahan -s."
    },
    {
        question: "If I see him, I ______ him the news.",
        options: ["tell", "told", "will tell", "telling"],
        answer: 2,
        explanation: "Klausa 'If' sudah present (see), maka klausa utama harus future 'will tell'."
    },
    {
        question: "Mom ______ happy if I clean my room.",
        options: ["is", "was", "will be", "be"],
        answer: 2,
        explanation: "Result clause memerlukan 'will'. Karena kata sifat 'happy' bukan kata kerja, kita butuh 'be' setelah 'will'. Jadi: 'will be'."
    },
    {
        question: "If the sun shines, we ______ to the beach.",
        options: ["go", "goes", "will go", "went"],
        answer: 2,
        explanation: "Conditional Type 1 memprediksi masa depan. Gunakan 'will go'."
    },
    {
        question: "If John ______ fast, he will win the race.",
        options: ["run", "runs", "ran", "running"],
        answer: 1,
        explanation: "Subjek 'John' (he) memerlukan verb+s, yaitu 'runs'."
    },
    {
        question: "I will call you if I ______ your help.",
        options: ["needs", "need", "needed", "will need"],
        answer: 1,
        explanation: "Jangan gunakan 'will' di dalam klausa 'If'. Gunakan Simple Present: 'need' untuk subjek 'I'."
    },

    // --- INTERMEDIATE LEVEL (16-40) ---
    // Fokus: Kalimat negatif (won't/don't), Kalimat tanya, penggunaan 'Unless', modal lain (can/may), variasi posisi klausa.

    {
        question: "Unless you ______, you will miss the train.",
        options: ["hurry", "hurries", "hurried", "will hurry"],
        answer: 0,
        explanation: "'Unless' artinya 'If... not', tapi strukturnya tetap mengikuti aturan If Clause (Simple Present). Subjek 'you' memakai 'hurry'."
    },
    {
        question: "What ______ if they don't agree?",
        options: ["happen", "happens", "will happen", "happened"],
        answer: 2,
        explanation: "Ini adalah bentuk pertanyaan untuk result clause. Gunakan Future Tense: 'will happen'."
    },
    {
        question: "If she doesn't practice, she ______ better.",
        options: ["won't get", "don't get", "doesn't get", "didn't get"],
        answer: 0,
        explanation: "Result clause bentuk negatif future adalah 'will not' atau disingkat 'won't'."
    },
    {
        question: "You can go out if you ______ your homework.",
        options: ["finish", "will finish", "finished", "finishes"],
        answer: 0,
        explanation: "Setelah 'if' tidak boleh ada 'will'. Subjek 'you' menggunakan V1 'finish'."
    },
    {
        question: "If the weather is bad, the flight ______ canceled.",
        options: ["is", "will be", "are", "was"],
        answer: 1,
        explanation: "Bentuk pasif di masa depan: 'will be' + V3 (canceled)."
    },
    {
        question: "I won't pay the bill unless the service ______ good.",
        options: ["is", "are", "will be", "was"],
        answer: 0,
        explanation: "Setelah 'unless' kita pakai Present Tense. Subjek 'service' (uncountable) pasangannya adalah 'is'."
    },
    {
        question: "If you ______ to the meeting, tell me.",
        options: ["don't go", "won't go", "didn't go", "not go"],
        answer: 0,
        explanation: "Klausa If negatif Present Tense untuk 'you' adalah 'don't go'."
    },
    {
        question: "If he ______ careful, he will fall.",
        options: ["isn't", "aren't", "won't be", "don't be"],
        answer: 0,
        explanation: "Bentuk negatif 'to be' dalam Present Tense untuk 'he' adalah 'is not' (isn't)."
    },
    {
        question: "Will you stay here if I ______ late?",
        options: ["am", "will be", "was", "were"],
        answer: 0,
        explanation: "Klausa 'if' tidak boleh pakai 'will'. Gunakan 'am' untuk subjek 'I'."
    },
    {
        question: "If anyone ______, tell them I am busy.",
        options: ["call", "calls", "calling", "called"],
        answer: 1,
        explanation: "Subjek 'anyone' dianggap tunggal (singular), jadi verb harus ditambah -s ('calls')."
    },
    {
        question: "We ______ on a picnic if it doesn't rain.",
        options: ["go", "might go", "went", "going"],
        answer: 1,
        explanation: "Dalam Type 1, kita bisa menggunakan modal lain seperti 'might' (mungkin) untuk menggantikan 'will' jika tidak 100% yakin."
    },
    {
        question: "If your phone ______, will you answer it?",
        options: ["ring", "rings", "rang", "will ring"],
        answer: 1,
        explanation: "Subjek 'your phone' adalah tunggal (it), maka verb menjadi 'rings'."
    },
    {
        question: "Unless he ______ apologize, I will not speak to him.",
        options: ["do", "does", "will", "did"],
        answer: 1,
        explanation: "Di sini kita butuh auxiliary verb untuk penekanan atau struktur kalimat. Untuk 'he', kita pakai 'does'."
    },
    {
        question: "If you don't water the plants, they ______.",
        options: ["die", "died", "will die", "dying"],
        answer: 2,
        explanation: "Prediksi masa depan (akibat), gunakan Future 'will die'. (Catatan: 'die' saja bisa untuk Type 0, tapi 'will die' lebih tepat untuk kejadian spesifik Type 1)."
    },
    {
        question: "She ______ angry if you forget her birthday.",
        options: ["is going to be", "was", "were", "is"],
        answer: 0,
        explanation: "'Is going to be' adalah bentuk lain dari Future Tense yang setara dengan 'will be' dalam konteks ini."
    },
    {
        question: "If the tickets ______ expensive, we won't buy them.",
        options: ["is", "are", "be", "will be"],
        answer: 1,
        explanation: "Subjek 'tickets' adalah jamak, jadi to be Present Tense-nya adalah 'are'."
    },
    {
        question: "What will she do if she ______ the job?",
        options: ["doesn't get", "won't get", "not get", "didn't get"],
        answer: 0,
        explanation: "Klausa If negatif untuk orang ketiga tunggal (she) menggunakan 'doesn't'."
    },
    {
        question: "If you ______ too much salt, the soup will taste bad.",
        options: ["added", "add", "adds", "will add"],
        answer: 1,
        explanation: "Instruksi/Saran. Subjek 'you' menggunakan 'add'."
    },
    {
        question: "I ______ you if I find your keys.",
        options: ["text", "texted", "will text", "texts"],
        answer: 2,
        explanation: "Janji di masa depan. Gunakan 'will text'."
    },
    {
        question: "If nothing ______, we will continue the plan.",
        options: ["change", "changes", "changed", "will change"],
        answer: 1,
        explanation: "Subjek 'nothing' adalah Indefinite Pronoun yang bersifat tunggal, jadi verb harus 'changes'."
    },
    {
        question: "You ______ weight if you stop exercising.",
        options: ["gain", "gained", "will gain", "gaining"],
        answer: 2,
        explanation: "Prediksi akibat. Gunakan 'will gain'."
    },
    {
        question: "If the traffic is heavy, I ______ late.",
        options: ["may be", "am", "was", "were"],
        answer: 0,
        explanation: "'May' adalah modal yang bisa digunakan di Type 1 untuk menunjukkan kemungkinan (possibility), sama fungsinya dengan 'will' tapi kurang pasti."
    },
    {
        question: "Unless they ______ the price, nobody will buy it.",
        options: ["lower", "lowers", "lowered", "will lower"],
        answer: 0,
        explanation: "Subjek 'they' menggunakan verb dasar 'lower'."
    },
    {
        question: "If I ______ the lottery, I will travel the world.",
        options: ["win", "wins", "won", "winning"],
        answer: 0,
        explanation: "Type 1 (Real possibility). Jika ini Type 2 (khayalan), kita pakai 'won'. Tapi untuk Type 1 strukturnya If + Present (win)."
    },
    {
        question: "If you ______ that button, the machine stops.",
        options: ["press", "pressed", "will press", "presses"],
        answer: 0,
        explanation: "Ini bisa jadi Type 0 atau Type 1. Namun dalam opsi grammar, 'press' adalah satu-satunya bentuk Present Tense yang benar untuk 'you'."
    },

    // --- EXPERT LEVEL (41-50) ---
    // Fokus: Kosa kata formal/bisnis, struktur pasif, inversi (Should...), long sentences, complex grammar nuances.

    {
        question: "If the contract ______ by tomorrow, we will proceed with the project.",
        options: ["sign", "signs", "is signed", "will be signed"],
        answer: 2,
        explanation: "Klausa If membutuhkan Passive Voice (Present Tense). Contract 'ditandatangani' (is signed), bukan menandatangani."
    },
    {
        question: "______ you need any assistance, please do not hesitate to call.",
        options: ["If", "Should", "Unless", "Will"],
        answer: 1,
        explanation: "Inversi formal untuk First Conditional. 'Should you need' setara dengan 'If you need'. Ini sangat umum di Business English."
    },
    {
        question: "The company will face bankruptcy if the merger ______.",
        options: ["fails", "fail", "failed", "will fail"],
        answer: 0,
        explanation: "Subjek 'the merger' adalah tunggal. Verb harus 'fails'. Jangan terkecoh dengan panjang kalimat."
    },
    {
        question: "If these criteria ______, the application will be rejected.",
        options: ["is not met", "are not met", "won't meet", "don't meet"],
        answer: 1,
        explanation: "Subjek 'criteria' adalah bentuk jamak dari 'criterion'. Jadi harus menggunakan 'are'. Kalimat ini juga bentuk pasif (are not met)."
    },
    {
        question: "Unless the government ______, the economy will suffer.",
        options: ["intervene", "intervenes", "intervened", "will intervene"],
        answer: 1,
        explanation: "Subjek 'the government' dianggap sebagai entitas tunggal (collective noun singular), jadi verb menggunakan 'intervenes'."
    },
    {
        question: "We will have to cancel the event provided that it ______.",
        options: ["rain", "rains", "will rain", "raining"],
        answer: 1,
        explanation: "'Provided that' berfungsi sama seperti 'If'. Aturan grammar tetap sama: Present Tense (rains) untuk subjek 'it'."
    },
    {
        question: "If the data analysis ______ correct, our strategy will succeed.",
        options: ["prove", "proves", "proving", "will prove"],
        answer: 1,
        explanation: "Subjek 'analysis' (tunggal) memerlukan verb 'proves'. Hati-hati dengan kata benda sebelumya 'data', intinya adalah 'analysis'."
    },
    {
        question: "Should the client ______ his mind, we will need a new proposal.",
        options: ["change", "changes", "changed", "will change"],
        answer: 0,
        explanation: "Setelah inversi 'Should' + Subject, kata kerja kembali ke bentuk dasar (Bare Infinitive) tanpa 's'. Jadi 'change', bukan 'changes'."
    },
    {
        question: "If proper safety measures ______, accidents will happen.",
        options: ["aren't taken", "isn't taken", "don't take", "won't take"],
        answer: 0,
        explanation: "Bentuk Passive Voice negatif jamak. Measures 'tidak diambil' (are not taken)."
    },
    {
        question: "The CEO will resign if the board of directors ______ confidence in him.",
        options: ["lose", "loses", "lost", "will lose"],
        answer: 1,
        explanation: "'The board of directors' biasanya diperlakukan sebagai satu unit tunggal (singular body), sehingga verb yang tepat adalah 'loses'."
    }
];