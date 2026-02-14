const questionsSource = [
    // --- TO BE (AM, IS, ARE) ---
    {
        question: "If you ______ ice, it melts.",
        options: ["heat", "heated", "heating", "will heat"],
        answer: 0,
        explanation: "Zero Conditional digunakan untuk fakta ilmiah. Polanya: If + Simple Present, Simple Present. Kata kerja yang tepat untuk subjek 'you' adalah 'heat' (V1)."
    },
    {
        question: "If it rains, the grass ______ wet.",
        options: ["getting", "get", "gets", "got"],
        answer: 2,
        explanation: "Dalam Simple Present Tense, jika subjeknya tunggal (the grass/it), kata kerja harus ditambahkan akhiran -s/es. Jadi, 'gets' adalah jawaban yang benar."
    },
    {
        question: "People ______ hungry if they don't eat.",
        options: ["get", "got", "gets", "getting"],
        answer: 0,
        explanation: "Subjeknya adalah 'People' (jamak), sehingga kita menggunakan kata kerja dasar (V1) yaitu 'get' tanpa tambahan -s."
    },
    {
        question: "If you touch fire, you ______ burned.",
        options: ["get", "gets", "will get", "got"],
        answer: 0,
        explanation: "Zero Conditional tidak menggunakan 'will'. Polanya adalah Present Tense di kedua klausa. Subjek 'you' menggunakan verb 'get'."
    },
    {
        question: "Babies ______ if they are hungry.",
        options: ["cries", "cry", "cried", "crying"],
        answer: 1,
        explanation: "Subjek 'Babies' adalah jamak, jadi kata kerjanya tidak perlu akhiran -s. Jawaban yang tepat adalah 'cry'."
    },
    {
        question: "If you mix red and blue, you ______ purple.",
        options: ["got", "get", "gets", "getting"],
        answer: 1,
        explanation: "Fakta umum pencampuran warna. Subjek 'you' diikuti oleh Verb 1 murni, yaitu 'get'."
    },
    {
        question: "If I wake up late, I ______ late for school.",
        options: ["am", "is", "be", "was"],
        answer: 0,
        explanation: "Untuk subjek 'I' dalam Simple Present Tense, to be yang digunakan adalah 'am'."
    },
    {
        question: "Snakes ______ if they are scared.",
        options: ["bite", "bites", "bit", "biting"],
        answer: 0,
        explanation: "Subjek 'Snakes' (jamak) menggunakan Verb 1 tanpa -s, yaitu 'bite'."
    },
    {
        question: "If my husband ______ food, he burns it.",
        options: ["cook", "cooks", "cooking", "cooked"],
        answer: 1,
        explanation: "Subjek 'my husband' adalah orang ketiga tunggal (he), sehingga kata kerja 'cook' harus ditambah -s menjadi 'cooks'."
    },
    {
        question: "If Julie ______ a hat, she looks simpler.",
        options: ["wear", "wearing", "wears", "wore"],
        answer: 2,
        explanation: "Subjek 'Julie' (she) memerlukan verb dengan akhiran -s dalam Simple Present, yaitu 'wears'."
    },
    {
        question: "Plants die if they ______ enough water.",
        options: ["don't get", "doesn't get", "didn't get", "not get"],
        answer: 0,
        explanation: "Kalimat negatif Simple Present untuk subjek 'they' (plants) menggunakan 'do not' atau 'don't'."
    },
    {
        question: "If you ______ water to 100 degrees, it boils.",
        options: ["heated", "heats", "heat", "heating"],
        answer: 2,
        explanation: "Subjek 'you' selalu diikuti Verb 1 tanpa tambahan s/es, jadi 'heat' adalah yang benar."
    },
    {
        question: "Does ice melt if you ______ it in the sun?",
        options: ["put", "puts", "putting", "putt"],
        answer: 0,
        explanation: "Meskipun ini kalimat tanya, klausa 'if' tetap mengikuti pola Simple Present. Subjek 'you' menggunakan 'put'."
    },
    {
        question: "If the sun sets, it ______ dark.",
        options: ["become", "becoming", "became", "becomes"],
        answer: 3,
        explanation: "Result clause memiliki subjek 'it', jadi kata kerja 'become' harus ditambah -s menjadi 'becomes'."
    },
    {
        question: "Iron rusts if it ______ wet.",
        options: ["get", "got", "gets", "getting"],
        answer: 2,
        explanation: "Subjek 'it' (mengacu pada iron) adalah tunggal, maka verb harus 'gets'."
    },

    // --- INTERMEDIATE LEVEL (16-40) ---
    // Fokus: Membalik urutan klausa, penggunaan 'When' sebagai pengganti 'If', kalimat negatif, subjek yang sedikit lebih kompleks.

    {
        question: "The engine starts if you ______ the key.",
        options: ["turned", "turn", "turns", "will turn"],
        answer: 1,
        explanation: "Klausa 'If' ada di belakang. Aturannya tetap sama: If + Present Simple. Subjek 'you' menggunakan 'turn'."
    },
    {
        question: "When the sun goes down, it ______ colder.",
        options: ["got", "get", "gets", "getting"],
        answer: 2,
        explanation: "Dalam Zero Conditional, 'when' sering menggantikan 'if' untuk sesuatu yang pasti terjadi. Result clause subjek 'it' menggunakan 'gets'."
    },
    {
        question: "If we ______ mask, we catch the virus easily.",
        options: ["don't wear", "doesn't wear", "didn't wear", "not wear"],
        answer: 0,
        explanation: "Kalimat negatif untuk subjek 'we' dalam Present Tense menggunakan auxiliary 'do not' (don't)."
    },
    {
        question: "Usually, if I exercise, I ______ better.",
        options: ["feels", "felt", "feel", "feeling"],
        answer: 2,
        explanation: "Menyatakan kebiasaan (habit). Subjek 'I' bertemu dengan verb 'feel' tanpa tambahan apapun."
    },
    {
        question: "My boss ______ angry if I am late.",
        options: ["get", "gets", "getting", "got"],
        answer: 1,
        explanation: "Subjek utama adalah 'My boss' (he/she), maka verb harus menggunakan akhiran -s, yaitu 'gets'."
    },
    {
        question: "If you don't brush your teeth, you ______ cavities.",
        options: ["gets", "got", "get", "getting"],
        answer: 2,
        explanation: "Logika sebab-akibat. Subjek 'you' pada result clause menggunakan Verb 1 'get'."
    },
    {
        question: "Does the light turn on if you ______ that switch?",
        options: ["press", "presses", "pressed", "pressing"],
        answer: 0,
        explanation: "Dalam pertanyaan Zero Conditional, klausa if tetap present simple. 'You' berpasangan dengan 'press'."
    },
    {
        question: "Computers ______ if you disconnect the power.",
        options: ["work", "works", "doesn't work", "don't work"],
        answer: 3,
        explanation: "Secara logika, komputer *tidak* bekerja jika listrik dicabut. Subjek 'Computers' (jamak) menggunakan negatif 'don't work'."
    },
    {
        question: "If milk ______ not refrigerated, it goes sour.",
        options: ["is", "are", "am", "be"],
        answer: 0,
        explanation: "Milk adalah uncountable noun (dianggap tunggal/it), jadi to be yang tepat adalah 'is'."
    },
    {
        question: "When people smoke cigarettes, their health ______.",
        options: ["suffer", "suffers", "suffered", "suffering"],
        answer: 1,
        explanation: "Subjek result clause adalah 'their health' (uncountable/singular), jadi verb menggunakan akhiran -s ('suffers')."
    },
    {
        question: "If you mix oil and water, it ______.",
        options: ["don't mix", "doesn't mix", "didn't mix", "won't mix"],
        answer: 1,
        explanation: "Subjek 'it' (campuran tadi) adalah tunggal. Bentuk negatif present tense untuk tunggal adalah 'doesn't'."
    },
    {
        question: "Does your teacher ______ annoyed if you use your phone in class?",
        options: ["gets", "get", "got", "getting"],
        answer: 1,
        explanation: "Karena sudah ada auxiliary 'Does' di awal kalimat tanya, kata kerja utama kembali ke bentuk dasar (V1), yaitu 'get', bukan 'gets'."
    },
    {
        question: "If I ______ too much coffee, I can't sleep at night.",
        options: ["drink", "drinks", "drank", "drunk"],
        answer: 0,
        explanation: "Kebiasaan pribadi. Subjek 'I' menggunakan Verb 1 'drink'."
    },
    {
        question: "Wood doesn't burn if there ______ no oxygen.",
        options: ["is", "are", "were", "was"],
        answer: 0,
        explanation: "Oxygen adalah uncountable noun, jadi menggunakan to be tunggal 'is'."
    },
    {
        question: "When you ______ by plane, you need a passport.",
        options: ["traveled", "travels", "travel", "traveling"],
        answer: 2,
        explanation: "Penggunaan 'When' dalam konteks aturan umum. Subjek 'you' menggunakan 'travel'."
    },
    {
        question: "A dog ______ its tail if it is happy.",
        options: ["wag", "wags", "wagging", "wagged"],
        answer: 1,
        explanation: "Subjek 'A dog' adalah tunggal (it), maka kata kerja 'wag' (mengibaskan) ditambah -s menjadi 'wags'."
    },
    {
        question: "If you ______ water in the freezer, it becomes ice.",
        options: ["puts", "put", "putting", "putt"],
        answer: 1,
        explanation: "Instruksi/Fakta. Subjek 'you' menggunakan 'put'."
    },
    {
        question: "When I am tired, I ______ to bed early.",
        options: ["go", "goes", "went", "gone"],
        answer: 0,
        explanation: "Kebiasaan (habit). Subjek 'I' menggunakan 'go'."
    },
    {
        question: "If the temperature ______ below zero, water freezes.",
        options: ["drop", "drops", "dropped", "dropping"],
        answer: 1,
        explanation: "Subjek 'the temperature' adalah tunggal (it), jadi verb harus 'drops'."
    },
    {
        question: "The alarm ______ off if there is smoke.",
        options: ["go", "goes", "went", "gone"],
        answer: 1,
        explanation: "Subjek 'The alarm' adalah tunggal, verb 'go' ditambah -es menjadi 'goes'."
    },
    {
        question: "If you ______ 'Delete', the file is lost.",
        options: ["pressed", "press", "presses", "pressing"],
        answer: 1,
        explanation: "Instruksi pada komputer (fakta). Subjek 'you' menggunakan 'press'."
    },
    {
        question: "You ______ weight if you eat too much junk food.",
        options: ["gain", "gains", "gained", "gaining"],
        answer: 0,
        explanation: "Fakta kesehatan. Subjek 'You' diikuti 'gain' tanpa -s."
    },
    {
        question: "If a stranger ______ the house, the dog barks.",
        options: ["enter", "enters", "entering", "entered"],
        answer: 1,
        explanation: "Subjek 'a stranger' adalah tunggal (he/she), maka verb 'enter' menjadi 'enters'."
    },
    {
        question: "Chemical reactions ______ faster if you heat the solution.",
        options: ["occur", "occurs", "occurred", "occurring"],
        answer: 0,
        explanation: "Subjek 'Chemical reactions' adalah jamak, jadi verb tetap dasar 'occur'."
    },
    {
        question: "When it ______, the road becomes slippery.",
        options: ["snow", "snows", "snowed", "snowing"],
        answer: 1,
        explanation: "Subjek 'it' (cuaca) memerlukan verb dengan akhiran -s, yaitu 'snows'."
    },

    // --- EXPERT LEVEL (41-50) ---
    // Fokus: Kosa kata tingkat lanjut (akademis/sains), struktur kalimat pasif, dan nuansa logika yang lebih dalam.

    {
        question: "If the atmospheric pressure decreases, the boiling point of water ______.",
        options: ["drop", "drops", "dropped", "will drop"],
        answer: 1,
        explanation: "Konteks fisika. Subjek 'the boiling point' adalah frasa benda tunggal (it), sehingga verb utama harus 'drops'. Jangan terkecoh dengan 'water'."
    },
    {
        question: "If supply ______ demand, prices usually fall.",
        options: ["exceed", "exceeds", "exceeded", "exceeding"],
        answer: 1,
        explanation: "Prinsip ekonomi. Subjek 'supply' (uncountable/singular) memerlukan verb dengan akhiran -s, yaitu 'exceeds'."
    },
    {
        question: "Photosynthesis ______ if plants are deprived of sunlight.",
        options: ["stop", "stops", "stopped", "stopping"],
        answer: 1,
        explanation: "Istilah biologi. Subjek 'Photosynthesis' adalah tunggal, jadi menggunakan 'stops'. Klausa kedua menggunakan bentuk pasif 'are deprived'."
    },
    {
        question: "If a number is multiplied by zero, the result ______ always zero.",
        options: ["is", "are", "be", "was"],
        answer: 0,
        explanation: "Logika matematika. Subjek result clause 'the result' adalah tunggal, jadi to be-nya adalah 'is'."
    },
    {
        question: "Unless he ______ allergic, he eats peanuts.",
        options: ["is", "are", "be", "was"],
        answer: 0,
        explanation: "'Unless' bermakna 'If... not'. Struktur grammar tetap mengikuti Present Simple. Subjek 'he' menggunakan 'is'."
    },
    {
        question: "If potential difference is applied across a conductor, current ______.",
        options: ["flow", "flows", "flowed", "flowing"],
        answer: 1,
        explanation: "Konteks fisika listrik. Subjek 'current' (arus) adalah uncountable noun (tunggal), jadi verb-nya adalah 'flows'."
    },
    {
        question: "When a person ______ from dehydration, their cognitive function declines.",
        options: ["suffer", "suffers", "suffered", "suffering"],
        answer: 1,
        explanation: "Subjek 'a person' adalah tunggal. Verb harus 'suffers'. Kalimat ini menunjukkan hubungan medis sebab-akibat yang permanen."
    },
    {
        question: "If litigation is pursued, legal costs ______ significantly.",
        options: ["increase", "increases", "increased", "increasing"],
        answer: 0,
        explanation: "Subjek 'legal costs' adalah jamak (costs), oleh karena itu verb yang digunakan adalah bentuk dasar 'increase' tanpa -s."
    },
    {
        question: "The subconscious mind ______ active even if the body sleeps.",
        options: ["remain", "remains", "remained", "remaining"],
        answer: 1,
        explanation: "Subjek 'The subconscious mind' adalah tunggal, jadi verb 'remain' menjadi 'remains'."
    },
    {
        question: "Metals ______ when they are heated.",
        options: ["expand", "expands", "expanded", "expanding"],
        answer: 0,
        explanation: "Hukum fisika dasar. Subjek 'Metals' jamak, jadi verb-nya 'expand' (tanpa s). Pilihan ini mengecoh jika siswa hanya melihat 'expand/expands' tanpa melihat subjek jamak."
    }
];