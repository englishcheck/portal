const questionsSource = [
    {
        question: "Not until the late 1960s ______ to understand the true complexity of the ecosystem.",
        options: ["did ecologists begin", "ecologists began", "began ecologists", "the beginning of ecologists"],
        answer: 0,
        explanation: "Pola Inversi: Ketika kalimat dimulai dengan frasa negatif seperti 'Not until', subjek dan kata kerja bantu (auxiliary verb) harus dibalik. Jadi, 'did ecologists begin' adalah susunan yang benar (Auxiliary + Subject + Verb)."
    },
    {
        question: "_______, the jaguar used to roam freely across the southwestern United States.",
        options: ["Found now mostly in Central and South America", "It is found now mostly in Central and South America", "To find it now mostly in Central and South America", "Now finding mostly in Central and South America"],
        answer: 0,
        explanation: "Reduced Adjective Clause (Past Participle): Frasa ini berasal dari 'Which is found now...'. Karena memiliki subjek yang sama dengan klausa utama (the jaguar) dan berbentuk pasif, kita bisa menghilangkan 'which is' dan menyisakan verb-3 (Found)."
    },
    {
        question: "Had the damage been worse, the pilot _______ able to land the plane safely.",
        options: ["would not have been", "will not have been", "would not be", "is not being"],
        answer: 0,
        explanation: "Conditional Sentence Type 3 (Inverted): Kalimat ini adalah bentuk inversi dari 'If the damage had been worse'. Konsekuensi untuk masa lalu (past unreal condition) menggunakan pola 'would have + V3'. Karena konteks negatif, menjadi 'would not have been'."
    },
    {
        question: "The professor suggested that the student _______ his research topic immediately.",
        options: ["changes", "changed", "change", "would change"],
        answer: 2,
        explanation: "Subjunctive Mood: Kata kerja tertentu seperti 'suggest', 'recommend', 'insist' diikuti oleh 'that' clause yang menggunakan bentuk dasar kata kerja (bare infinitive), tanpa 's', 'ed', atau 'ing', terlepas dari subjeknya."
    },
    {
        question: "_______ classified as a carnivore, the North American Giant Panda eats almost exclusively bamboo.",
        options: ["Although", "But", "Despite", "In spite of"],
        answer: 0,
        explanation: "Conjunction vs Preposition: 'Classified' di sini adalah bagian dari reduced clause 'Although it is classified...'. Kita membutuhkan conjunction (kata hubung) seperti 'Although'. 'Despite' dan 'In spite of' adalah preposisi yang harus diikuti benda (noun), bukan past participle."
    },
    {
        question: "Rarely _______ such a dramatic increase in the stock market in a single day.",
        options: ["we have seen", "have we seen", "seen we have", "we saw"],
        answer: 1,
        explanation: "Inversion dengan Negative Adverb: Kata 'Rarely' di awal kalimat memicu inversi. Susunannya menjadi: Negative Adverb + Auxiliary + Subject + Verb ('have we seen')."
    },
    {
        question: "The higher the content of carbon dioxide in the air, _______.",
        options: ["more heat it retains", "the more heat it retains", "it retains more heat", "than it retains more heat"],
        answer: 1,
        explanation: "Double Comparative: Pola 'The + comparative ..., the + comparative ...' digunakan untuk menunjukkan korelasi. Jawaban yang benar mengikuti pola kedua: 'the more heat it retains'."
    },
    {
        question: "Only by working three jobs _______ to support his large family.",
        options: ["he was able", "was he able", "he is able", "able he was"],
        answer: 1,
        explanation: "Inversion dengan 'Only': Frasa yang diawali dengan 'Only' (seperti 'Only by...') yang diletakkan di awal kalimat mengharuskan inversi subjek dan auxiliary verb ('was he')."
    },
    {
        question: "Unlike most birds, _______.",
        options: ["the heads of owls cannot turn", "owls can turn their heads 270 degrees", "it is the owl that turns its head", "turning the head is easy for owls"],
        answer: 1,
        explanation: "Logical Comparison: Setelah 'Unlike most birds', subjek kalimat utama haruslah noun yang sebanding dengan 'most birds'. 'Owls' adalah subjek yang paling logis dan setara untuk dibandingkan."
    },
    {
        question: "_______ gene therapy serves as a viable treatment for genetic disorders remains to be seen.",
        options: ["Whether", "If", "That", "When"],
        answer: 0,
        explanation: "Noun Clause sebagai Subjek: Kalimat ini membutuhkan subjek berupa klausa. 'Whether' (apakah) adalah pilihan yang tepat untuk menyatakan ketidakpastian ('remains to be seen'). 'If' tidak lazim digunakan di awal kalimat sebagai subjek."
    },
    {
        question: "New York City’s Central Park is nearly twice _______ the entire principality of Monaco.",
        options: ["as large as", "large as", "as large", "larger than"],
        answer: 0,
        explanation: "Multiple Number Comparison: Setelah kata kelipatan (twice, three times, etc.), kita menggunakan pola 'as + adjective + as'. Jadi, 'twice as large as' adalah bentuk yang benar."
    },
    {
        question: "Little _______ that the surprise party was being planned right under his nose.",
        options: ["did he suspect", "he suspected", "was he suspected", "suspected he"],
        answer: 0,
        explanation: "Inversion dengan 'Little': 'Little' dengan makna negatif (sedikit sekali/tidak sama sekali) di awal kalimat memicu inversi: Auxiliary (did) + Subject (he) + Verb (suspect)."
    },
    {
        question: "_______ for the advice of his financial advisor, he would have gone bankrupt.",
        options: ["Had it not been", "If it has not been", "Unless it had been", "Were it not"],
        answer: 0,
        explanation: "Conditional Sentence (Inverted): Ini adalah bentuk inversi dari 'If it had not been for...' (Seandainya bukan karena...). Polanya adalah 'Had + Subject + V3'."
    },
    {
        question: "Ideally, the overarching goal of a business should be to serve the community _______ a profit.",
        options: ["as well as making", "and also to make", "while making", "nor make"],
        answer: 2,
        explanation: "Reduced Adverbial Clause: 'While making' adalah bentuk ringkas dari 'while it is making'. Pilihan B salah karena 'to serve' dan 'to make' akan paralel, tapi 'and also' membuatnya berlebihan (wordy), dan C lebih mengalir secara idiomatis untuk tindakan bersamaan."
    },
    {
        question: "_______ native to North America, the Jerusalem artichoke is actually a species of sunflower.",
        options: ["Although", "Despite", "Whatever", "However"],
        answer: 0,
        explanation: "Conjunction pada Reduced Clause: 'Although (it is) native to...' adalah penggunaan yang tepat. Kata hubung kontradiktif diperlukan di sini."
    },
    {
        question: "Never before in the history of the company _______ such a profitable quarter.",
        options: ["has there been", "there has been", "have been there", "it has been"],
        answer: 0,
        explanation: "Inversion dengan 'Never': Frasa waktu negatif di awal kalimat memicu inversi. Subject 'there' bertukar tempat dengan auxiliary 'has'."
    },
    {
        question: "_______ determination to succeed that he overcame every obstacle in his path.",
        options: ["So great was his", "Such was his", "His was such", "So his was"],
        answer: 1,
        explanation: "Inversion dengan 'Such... that': Pola 'Such be noun... that...' digunakan untuk penekanan. 'Such was his determination...' setara dengan 'His determination was so great...'."
    },
    {
        question: "_______ primarily a vegetarian, the chimpanzee also eats meat occasionally.",
        options: ["Although", "However", "In spite of", "Even"],
        answer: 0,
        explanation: "Reduced Adjective Clause: 'Although (it is) primarily a vegetarian...'. Kita butuh conjunction yang diikuti adjective/noun phrase dalam bentuk reduksi."
    },
    {
        question: "_______ received the award than he gave a humble acceptance speech.",
        options: ["No sooner had he", "Hardly had he", "Scarcely did he", "No sooner he had"],
        answer: 0,
        explanation: "Correlative Conjunction: Pasangan dari 'than' adalah 'No sooner'. Karena diletakkan di awal, terjadi inversi: 'No sooner had he...'."
    },
    {
        question: "_______ where the treasure was hidden, the pirates began digging furiously.",
        options: ["Knowing", "Known", "To know", "They knew"],
        answer: 0,
        explanation: "Present Participle Phrase (Active Meaning): Frasa ini menjelaskan subjek 'the pirates'. Karena bajak laut itu 'mengetahui' (aktif), kita menggunakan Verb-ing (Knowing)."
    },
    {
        question: "Only after checking the data three times _______ the report ready for publication.",
        options: ["the scientist considered", "did the scientist consider", "considered the scientist", "was the scientist considered"],
        answer: 1,
        explanation: "Inversion dengan 'Only after': Frasa preposisi yang diawali 'Only' memicu inversi pada klausa utama. Auxiliary 'did' muncul sebelum subjek."
    },
    {
        question: "_______ broadly speaking, the economy is showing signs of recovery.",
        options: ["Although", "Yet", "But", "While"],
        answer: 3,
        explanation: "Conjunction: 'While' sering digunakan dengan makna 'meskipun/walaupun' dalam konteks kontras (While broadly speaking...)."
    },
    {
        question: "Under no circumstances _______ the restricted area without proper authorization.",
        options: ["you should enter", "should you enter", "you enter", "enter you"],
        answer: 1,
        explanation: "Inversion dengan Negative Expression: 'Under no circumstances' bermakna negatif mutlak, sehingga memicu inversi modal auxiliary: 'should you enter'."
    },
    {
        question: "_______ kinetic energy, potential energy is stored energy.",
        options: ["Unlike", "Dislike", "Alike", "Likely"],
        answer: 0,
        explanation: "Preposition of Contrast: Untuk membandingkan dua benda yang berbeda sifat (kinetic vs potential), kita menggunakan preposisi 'Unlike'."
    },
    {
        question: "It is essential that every employee _______ the safety guidelines carefully.",
        options: ["reads", "read", "reading", "to read"],
        answer: 1,
        explanation: "Subjunctive Mood: Setelah ekspresi 'It is essential that...', verb dalam klausa 'that' harus berbentuk bare infinitive (dasar), yaitu 'read', meskipun subjeknya tunggal (employee)."
    },
    {
        question: "_______ a result of the collision, the stars merged to form a new galaxy.",
        options: ["As", "For", "With", "By"],
        answer: 0,
        explanation: "Idiomatic Phrase: Frasa yang benar adalah 'As a result of' (Sebagai hasil dari)."
    },
    {
        question: "Not only _______ effective, but it is also cost-efficient.",
        options: ["is the new method", "the new method is", "the new method be", "be the new method"],
        answer: 0,
        explanation: "Inversion dengan 'Not only': Ketika 'Not only' memulai kalimat, klausa pertama diinversi (Verb to be sebelum Subject). 'is the new method'."
    },
    {
        question: "_______ mammals, dolphins must surface to breathe air.",
        options: ["Being", "Are", "To be", "They are"],
        answer: 0,
        explanation: "Present Participle as Reason: 'Being mammals' bermakna 'Because they are mammals'. Ini adalah reduced adverbial clause of cause."
    },
    {
        question: "Whatever the outcome _______, we must accept it with grace.",
        options: ["be", "is", "may be", "will be"],
        answer: 2,
        explanation: "Noun Clause: Dalam struktur 'Whatever + noun + verb', 'may be' adalah bentuk yang paling tepat untuk menunjukkan kemungkinan di masa depan atau ketidakpastian."
    },
    {
        question: "_______ lay the ruins of the ancient city.",
        options: ["In the valley below", "Below the valley", "The valley below", "In below the valley"],
        answer: 0,
        explanation: "Inversion of Place: Ketika keterangan tempat diletakkan di depan (In the valley below) dan verb-nya intransitif (lay), subjek (the ruins) diletakkan di akhir."
    },
    {
        question: "Ismail Marzuki is a composer _______ works are celebrated throughout Indonesia.",
        options: ["who", "whom", "whose", "which"],
        answer: 2,
        explanation: "Relative Pronoun (Possessive): Kita membutuhkan kata ganti yang menunjukkan kepemilikan (karya milik komposer). 'Whose' adalah satu-satunya pilihan posesif untuk orang."
    },
    {
        question: "Were it not for the ozone layer, life on Earth _______ difficult to sustain.",
        options: ["would be", "will be", "is", "was"],
        answer: 0,
        explanation: "Conditional Type 2 (Inverted): 'Were it not for' adalah inversi dari 'If it were not for' (fakta saat ini). Klausa utamanya menggunakan 'would + verb 1'."
    },
    {
        question: "The director requested that the report _______ submitted by Friday.",
        options: ["be", "is", "was", "were"],
        answer: 0,
        explanation: "Subjunctive Passive: 'Requested that...' menuntut subjunctive. Bentuk pasif subjunctive selalu 'be + V3' (be submitted), bukan 'is' atau 'was'."
    },
    {
        question: "_______ largely by instinct, sea turtles return to the exact beach where they were hatched.",
        options: ["Guided", "Guiding", "To guide", "Guide"],
        answer: 0,
        explanation: "Past Participle Phrase (Passive Meaning): Penyu dipandu (guided) oleh insting, bukan memandu. Maka digunakan V3 'Guided'."
    },
    {
        question: "Scarcely had the game started _______ it began to rain.",
        options: ["than", "when", "then", "after"],
        answer: 1,
        explanation: "Correlative Conjunction: Pasangan dari 'Scarcely' atau 'Hardly' adalah 'when'. (Pasangan 'No sooner' adalah 'than')."
    },
    {
        question: "Physics, _______, seeks to understand the fundamental principles of the universe.",
        options: ["is a science", "a science", "as a science", "to be a science"],
        answer: 2,
        explanation: "Appositive/Phrase: 'As a science' menjelaskan peran Fisika. Pilihan B (Appositive) sebenarnya bisa benar jika tanpa koma setelah 'science', tapi 'as a science' lebih mengalir sebagai frasa preposisi penjelas dalam konteks kalimat ini."
    },
    {
        question: "_______ copper is a conductive metal, it is widely used in electrical wiring.",
        options: ["Because", "That", "For", "So"],
        answer: 0,
        explanation: "Adverbial Clause of Cause: Kita membutuhkan conjunction yang menyatakan alasan di awal kalimat. 'Because' adalah yang paling tepat."
    },
    {
        question: "_______, the experiment was deemed a failure.",
        options: ["Having been poorly designed", "Poorly designed", "Designing poorly", "Because designed poorly"],
        answer: 0,
        explanation: "Perfect Participle Phrase (Passive): Menekankan bahwa desain yang buruk terjadi *sebelum* eksperimen dianggap gagal. 'Having been + V3' menunjukkan urutan waktu dan bentuk pasif."
    },
    {
        question: "The more we learn about the universe, _______ we realize how little we know.",
        options: ["more", "the more", "mostly", "the most"],
        answer: 1,
        explanation: "Double Comparative: Pola 'The + comparative ..., the + comparative ...'. Jawaban harus menggunakan 'the more'."
    },
    {
        question: "Neither the manager nor the employees _______ aware of the new policy.",
        options: ["was", "were", "is", "has been"],
        answer: 1,
        explanation: "Subject-Verb Agreement (Correlative): Dalam konstruksi 'Neither... nor...', verb mengikuti subjek yang paling dekat dengannya. 'Employees' jamak, maka verb-nya 'were'."
    },
    {
        question: "_______ of the two candidates is qualified for the position.",
        options: ["Neither", "None", "No one", "Not one"],
        answer: 0,
        explanation: "Pronoun selection: 'Neither' digunakan untuk menunjuk 'tidak satupun' dari *dua* pilihan. 'None' digunakan untuk 3 atau lebih."
    },
    {
        question: "Generally, the behavior of gases is easier to predict than _______ of liquids.",
        options: ["that", "those", "one", "the one"],
        answer: 0,
        explanation: "Demonstrative Pronoun: 'That' digunakan untuk menggantikan noun tunggal (behavior) yang telah disebutkan sebelumnya untuk menghindari pengulangan. Jika jamak, gunakan 'those'."
    },
    {
        question: "_______ evidence implies that water once existed on Mars.",
        options: ["There is", "That", "What", "Much"],
        answer: 3,
        explanation: "Quantifier: 'Evidence' adalah uncountable noun. 'Much' bisa digunakan. Pilihan A membuat kalimat memiliki dua verb tanpa konektor. Pilihan B membuat fragment."
    },
    {
        question: "Never _______ allow your emotions to cloud your judgment.",
        options: ["you should", "should you", "you did", "did you"],
        answer: 1,
        explanation: "Inversion (Imperative context): Meskipun ini terlihat seperti perintah, penggunaan 'Never' di awal untuk penekanan biasanya diikuti 'should you' dalam konteks saran formal, atau langsung verb dasar (Never allow...). Namun, jika ada opsi inversi modal, itu lebih menekankan larangan."
    },
    {
        question: "The artist _______ painting was sold for millions is coming to the gallery.",
        options: ["who", "whom", "whose", "that"],
        answer: 2,
        explanation: "Relative Pronoun (Possessive): Mengacu pada lukisan milik artis tersebut, maka digunakan 'whose'."
    },
    {
        question: "_______ rapid technological advancements, privacy concerns have increased.",
        options: ["Because", "Due to", "Since", "Owing"],
        answer: 1,
        explanation: "Prepositional Phrase: 'Because' dan 'Since' harus diikuti klausa (S+V). 'Rapid technological advancements' adalah Noun Phrase, maka butuh preposisi 'Due to'. ('Owing' harus diikuti 'to')."
    },
    {
        question: "It was _______ excited about the trip that he couldn't sleep.",
        options: ["so", "such", "very", "too"],
        answer: 0,
        explanation: "So... that structure: Pola 'be + so + adjective + that'. 'Such' digunakan jika ada noun (such an exciting trip)."
    },
    {
        question: "Only when the dust settled _______ the extent of the damage.",
        options: ["they saw", "did they see", "saw they", "seen"],
        answer: 1,
        explanation: "Inversion: 'Only when...' di awal kalimat memicu inversi pada klausa utama (Auxiliary + S + V)."
    },
    {
        question: "_______ to catch the early train, we set two alarms.",
        options: ["Hoping", "To hope", "We hope", "Hoped"],
        answer: 0,
        explanation: "Present Participle Phrase: Menjelaskan alasan atau kegiatan subjek (We). 'Berharap' adalah makna aktif, jadi 'Hoping'."
    },
    {
        question: "By the time the police arrived, the thieves _______ escaped.",
        options: ["have", "had", "will have", "would have"],
        answer: 1,
        explanation: "Past Perfect: Digunakan untuk aksi yang sudah selesai (escaped) *sebelum* aksi lain di masa lampau terjadi (police arrived)."
    },
    {
        question: "_______ that the department needs to cut costs, the manager decided to forego the annual retreat.",
        options: ["Realizing", "Realized", "To realize", "Realization"],
        answer: 0,
        explanation: "Reduced Adverbial Clause (Active): Kalimat aslinya adalah 'Because the manager realized...'. Karena subjeknya sama (the manager) dan kalimatnya aktif (manajer yang menyadari), kita meringkasnya menjadi Present Participle (V-ing): 'Realizing'."
    },
    {
        question: "Not only _______ the report, but he also presented it to the board.",
        options: ["did he write", "he wrote", "wrote he", "he did write"],
        answer: 0,
        explanation: "Inversion with 'Not only': Ketika 'Not only' diletakkan di awal kalimat untuk penekanan, struktur kalimat harus diinversi (Auxiliary + Subject + Verb). Maka, 'did he write' adalah susunan yang tepat."
    },
    {
        question: "The committee insists that the budget _______ by the end of the week.",
        options: ["is approved", "be approved", "will be approved", "approve"],
        answer: 1,
        explanation: "Subjunctive Passive: Kata 'insist' memicu Subjunctive Mood. Aturannya adalah: 'that + subject + verb dasar (bare infinitive)'. Karena ini pasif (anggaran disetujui), maka bentuk dasarnya adalah 'be + V3' ('be approved'), bukan 'is approved'."
    },
    {
        question: "_______ largely due to its efficient public transport system, Tokyo is one of the most accessible cities in the world.",
        options: ["Is", "It is", "Being", "That is"],
        answer: 2,
        explanation: "Participial Phrase as Reason: Kita membutuhkan frasa yang menjelaskan *alasan* (sebab) tanpa membentuk kalimat penuh baru (karena akan menyebabkan run-on sentence). 'Being...' di sini bermakna 'Because it is...'."
    },
    {
        question: "Whatever the critics _______ about his latest film, the director remains confident in his artistic vision.",
        options: ["say", "says", "saying", "have said"],
        answer: 0,
        explanation: "Subject-Verb Agreement in Clauses: Subjek dari klausa 'Whatever...' adalah 'the critics' (jamak/plural). Maka verb-nya harus jamak: 'say'. Jangan terkecoh dengan 'Whatever' yang terlihat tunggal."
    },
    {
        question: "_______ a doctor, Tim was able to administer first aid immediately.",
        options: ["Was", "Being", "To be", "As"],
        answer: 1,
        explanation: "Reduced Clause of Cause: 'Because he was a doctor' diringkas menjadi 'Being a doctor'. Pilihan 'As' salah karena 'As a doctor' biasanya diikuti koma dan nama orangnya langsung sebagai subjek tanpa jeda logika yang panjang, namun 'Being' lebih tepat untuk menunjukkan *sebab/alasan* kemampuan dia."
    },
    {
        question: "Were it not for his quick thinking, the accident _______ catastrophic.",
        options: ["would have been", "will be", "is", "was"],
        answer: 0,
        explanation: "Inverted Conditional Type 3 (Mixed/Past Context): 'Were it not for' menandakan pengandaian masa lalu yang kontrafaktual (fakta yang tidak terjadi). Konsekuensi di masa lalu menggunakan 'would have + V3'."
    },
    {
        question: "The ancient manuscript, _______ dating back to the 4th century, was discovered in a remote cave.",
        options: ["believed to be", "believed it is", "which believed", "believing"],
        answer: 0,
        explanation: "Reduced Relative Clause (Passive): Asalnya adalah '...which is believed to be...'. Dalam reduksi pasif, kita menghilangkan 'which is' dan menyisakan V3 ('believed')."
    },
    {
        question: "Only by working together _______ to achieve our quarterly goals.",
        options: ["we can hope", "can we hope", "we hope", "hope we"],
        answer: 1,
        explanation: "Inversion with 'Only': Frasa 'Only by...' di awal kalimat mengharuskan inversi subjek dan modal/auxiliary. 'Can we hope' adalah bentuk yang benar."
    },
    {
        question: "_______ more information become available, we will update the website immediately.",
        options: ["Should", "If", "Had", "Were"],
        answer: 0,
        explanation: "Inverted Conditional Type 1: 'Should' di awal kalimat bisa menggantikan 'If'. Kalimat ini setara dengan 'If more information should become available...'. Ini bentuk formal untuk kemungkinan di masa depan."
    },
    {
        question: "The CEO demanded that the sheer magnitude of the error _______ immediately.",
        options: ["be investigated", "is investigated", "investigated", "to investigate"],
        answer: 0,
        explanation: "Subjunctive Passive: Kata 'demanded' memicu subjunctive. Verb harus dalam bentuk dasar ('be'). Karena pasif (kesalahan diselidiki), maka 'be investigated'."
    },
    {
        question: "Unlike the atmosphere of Mars, _______ contains enough oxygen to support life.",
        options: ["that of Earth", "Earth", "Earth's", "those of Earth"],
        answer: 0,
        explanation: "Logical Comparison: Kita membandingkan 'atmosphere' Mars dengan 'atmosphere' Bumi. 'Earth' saja salah (membandingkan atmosfer dengan planet). 'That of Earth' adalah kata ganti yang tepat untuk 'the atmosphere of Earth'."
    },
    {
        question: "So implies the contract _______ the tenant is responsible for all repairs.",
        options: ["that", "what", "which", "as"],
        answer: 0,
        explanation: "Noun Clause Construction: Struktur kalimat ini sedikit tidak biasa tapi valid: 'So implies the contract...' (Inversi). Yang diimplikasikan adalah sebuah fakta, maka kita butuh 'that' untuk memulai Noun Clause."
    },
    {
        question: "_______ giant pandas eat bamboo, they are technically carnivores.",
        options: ["Despite", "Even though", "However", "Nevertheless"],
        answer: 1,
        explanation: "Conjunction vs Preposition: Kita membutuhkan kata hubung yang diikuti oleh Klausa (Subject + Verb: 'giant pandas eat'). 'Despite' adalah preposisi (harus diikuti noun). 'Even though' adalah conjunction yang tepat."
    },
    {
        question: "Never before _______ experienced such a severe drought.",
        options: ["the region has", "has the region", "the region had", "did the region"],
        answer: 1,
        explanation: "Inversion with Negative Adverb: 'Never before' di awal kalimat memicu inversi Auxiliary + Subject. Menggunakan 'has' karena konteksnya present perfect (sampai sekarang)."
    },
    {
        question: "_______ hearing the news, she burst into tears.",
        options: ["On", "At", "In", "While"],
        answer: 0,
        explanation: "Idiomatic Preposition: 'On' (atau Upon) diikuti Gerund (V-ing) bermakna 'Segera setelah' (Immediately after). 'On hearing' = Segera setelah mendengar."
    },
    {
        question: "The hypothesis _______ by the data was rejected by the scientific community.",
        options: ["support", "supporting", "supported", "supports"],
        answer: 2,
        explanation: "Past Participle Phrase (Passive): Hipotesis tersebut *didukung* oleh data, bukan mendukung data. Jadi kita butuh bentuk pasif (V3) 'supported' yang merupakan reduksi dari 'which was supported'."
    },
    {
        question: "Scarcely had the plane taken off _______ the pilot reported an engine failure.",
        options: ["than", "when", "then", "as"],
        answer: 1,
        explanation: "Correlative Conjunction: Pasangan dari 'Scarcely' atau 'Hardly' selalu 'when'. (Ingat: No sooner... than, Scarcely... when)."
    },
    {
        question: "_______ classified as a distinct species, the organism shares many traits with algae.",
        options: ["Although", "Despite", "However", "Since"],
        answer: 0,
        explanation: "Reduced Clause Conjunction: 'Although (it is) classified...'. Kita butuh conjunction kontras untuk reduksi ini. 'Despite' tidak bisa diikuti langsung oleh V3 (participle) tanpa 'being'."
    },
    {
        question: "_______ gene editing technology allows for precise modifications is widely accepted.",
        options: ["That", "What", "Which", "Because"],
        answer: 0,
        explanation: "Noun Clause as Subject: Seluruh bagian sebelum 'is widely accepted' adalah subjek kalimat. 'That' berfungsi sebagai penanda bahwa kalimat 'gene editing technology allows...' adalah sebuah noun clause."
    },
    {
        question: "Under no circumstances _______ to leave the building unlocked.",
        options: ["are you", "you are", "should you", "you should"],
        answer: 0,
        explanation: "Inversion with Negative Expression: 'Under no circumstances' (jangan pernah) memicu inversi. Pilihan 'are you' lebih tepat untuk instruksi aturan/kewajiban status (You are not to leave...), atau 'should you' (tidak ada di opsi yang pas strukturnya dengan 'to'). Namun 'are you to leave' adalah struktur formal untuk larangan/perintah (be + to infinitive)."
    },
    {
        question: "_______ broken, the antique vase could not be restored.",
        options: ["Having been", "Has been", "Being", "To be"],
        answer: 0,
        explanation: "Perfect Participle Passive: Menekankan bahwa aksi pecah (broken) terjadi *sebelum* aksi tidak bisa diperbaiki. 'Having been broken' menunjukkan urutan waktu dan pasif."
    },
    {
        question: "The assumption _______ the economy will recover quickly is overly optimistic.",
        options: ["which", "that", "what", "where"],
        answer: 1,
        explanation: "Appositive Noun Clause: Klausa 'the economy will recover quickly' adalah isi dari 'assumption'. Ini bukan relative clause biasa, melainkan appositive yang menjelaskan isi noun tersebut, jadi gunakan 'that'."
    },
    {
        question: "_______ of the two options seems viable at this stage.",
        options: ["None", "Neither", "Not one", "No one"],
        answer: 1,
        explanation: "Quantifier for Two: Untuk memilih 'tidak satupun' dari *dua* pilihan, wajib menggunakan 'Neither'. 'None' untuk 3 atau lebih."
    },
    {
        question: "Usually, the more complex a system is, _______ prone to error it becomes.",
        options: ["more", "the more", "the most", "most"],
        answer: 1,
        explanation: "Double Comparative: 'The more complex..., the more prone...'. Pola paralel ini wajib menggunakan 'the' + comparative."
    },
    {
        question: "Whatever _______, we must remain calm.",
        options: ["happens", "happen", "happening", "to happen"],
        answer: 0,
        explanation: "Noun Clause Subject: Dalam klausa 'Whatever happens', 'Whatever' berfungsi sebagai subjek tunggal (singular subject), sehingga verb-nya 'happens'."
    },
    {
        question: "Had the government intervened earlier, the crisis _______ avoided.",
        options: ["could be", "would be", "might have been", "was"],
        answer: 2,
        explanation: "Conditional Type 3 (Inverted): Pengandaian masa lalu. Bagian 'result' harus menggunakan modal perfect (would/could/might + have + V3). 'Might have been avoided' adalah satu-satunya opsi yang benar secara gramatikal."
    },
    {
        question: "_______ considered a delicacy, caviar is actually processed fish eggs.",
        options: ["Though", "Despite", "In spite of", "However"],
        answer: 0,
        explanation: "Reduced Adjective Clause: 'Though (it is) considered...'. Kita butuh conjunction. 'Despite' harus diikuti Noun atau Gerund (Despite being considered...)."
    },
    {
        question: "The physicist hypothesized that dark matter, _______ invisible, exerts gravitational pull.",
        options: ["although", "despite", "however", "nevertheless"],
        answer: 0,
        explanation: "Reduced Clause Parenthetical: Sisipan 'although (it is) invisible' menjelaskan dark matter. 'Although' adalah conjunction yang paling tepat untuk reduksi adjective clause ini."
    },
    {
        question: "Not until the 20th century _______ fully appreciated.",
        options: ["was Van Gogh's work", "Van Gogh's work was", "did Van Gogh's work", "Van Gogh's work did"],
        answer: 0,
        explanation: "Inversion with 'Not until': Frasa waktu negatif di depan memicu inversi. Karena kalimatnya pasif (was appreciated), kita membalik 'was' dan subjeknya. 'Was Van Gogh's work...'."
    },
    {
        question: "Determine the mass of the object, _______ calculate its density.",
        options: ["and then", "after", "then", "subsequently"],
        answer: 0,
        explanation: "Coordinate Conjunction: Kalimat ini adalah dua perintah (imperative). Kita butuh 'and' untuk menghubungkannya. 'Then' saja adalah adverb, bukan conjunction, jadi '...object, then...' akan menjadi comma splice (salah). 'And then' adalah yang benar."
    },
    {
        question: "It is vital that he _______ the documents before signing.",
        options: ["reviews", "review", "reviewed", "reviewing"],
        answer: 1,
        explanation: "Subjunctive Mood: 'Vital' adalah kata sifat yang menunjukkan kepentingan (urgency), memicu subjunctive. Verb harus 'bare infinitive' (review), tanpa 's'."
    },
    {
        question: "_______ the harsh weather, the expedition continued.",
        options: ["Despite", "Although", "Even though", "Whereas"],
        answer: 0,
        explanation: "Preposition vs Conjunction: 'The harsh weather' adalah Noun Phrase. Kita butuh preposisi 'Despite'. 'Although' harus diikuti kalimat (S+V)."
    },
    {
        question: "Only if the board approves the budget _______ with the project.",
        options: ["we can proceed", "can we proceed", "we proceed", "proceed we"],
        answer: 1,
        explanation: "Inversion with 'Only if': Klausa 'Only if...' di awal kalimat memicu inversi pada klausa utama (induk kalimat). Auxiliary 'can' harus mendahului subjek 'we'."
    },
    {
        question: "The distinct geological features of the canyon are similar to _______.",
        options: ["Mars", "those on Mars", "that of Mars", "Mars's"],
        answer: 1,
        explanation: "Logical Comparison: Kita membandingkan 'geological features' (jamak). Maka kata gantinya adalah 'those' + preposisi. 'Those on Mars'."
    },
    {
        question: "_______ by the sheer number of applicants, the hiring manager extended the deadline.",
        options: ["Overwhelmed", "Overwhelming", "To overwhelm", "Overwhelm"],
        answer: 0,
        explanation: "Past Participle (Passive Meaning): Manajer tersebut *merasa kewalahan* (pasif), bukan menekan (aktif). Jadi gunakan V3 'Overwhelmed' sebagai ringkasan dari 'Because he was overwhelmed...'."
    },
    {
        question: "Rarely _______ such a display of talent in a young athlete.",
        options: ["one sees", "does one see", "sees one", "is one seeing"],
        answer: 1,
        explanation: "Inversion with Negative Adverb: 'Rarely' di awal kalimat memicu inversi. Gunakan 'does' (auxiliary) + subject + verb."
    },
    {
        question: "_______ creates a vacuum, drawing liquid up the straw.",
        options: ["Sucking on the straw", "By sucking on the straw", "When sucking on the straw", "The straw sucking"],
        answer: 0,
        explanation: "Gerund as Subject: Kita membutuhkan subjek untuk verb 'creates'. Gerund phrase 'Sucking on the straw' berfungsi sebagai noun/subjek."
    },
    {
        question: "The professor had the students _______ their essays.",
        options: ["rewrite", "to rewrite", "rewriting", "rewrote"],
        answer: 0,
        explanation: "Causative 'Have': Rumus Causative Active dengan 'Have' adalah: Subject + Have + Person + Verb 1 (Base form). Jadi, 'had the students rewrite'."
    },
    {
        question: "She would rather that he _______ tomorrow.",
        options: ["comes", "came", "come", "will come"],
        answer: 1,
        explanation: "Subjunctive with 'Would Rather': Jika subjeknya berbeda (She vs He) dan mengacu pada masa depan/sekarang, 'would rather' diikuti oleh Past Tense (Subjunctive). Jadi 'came' (bukan comes/will come)."
    },
    {
        question: "_______, the stronger the magnetic field.",
        options: ["The closer the poles", "Closer the poles", "The closer are the poles", "The poles are closer"],
        answer: 0,
        explanation: "Double Comparative: Pola 'The + comparative, the + comparative'. Verb 'be' sering dihilangkan (ellipsis) jika konteksnya jelas. 'The closer the poles (are)' adalah bentuk yang benar."
    },
    {
        question: "Not once _______ his promise to help.",
        options: ["he forgot", "did he forget", "he has forgotten", "forgot he"],
        answer: 1,
        explanation: "Inversion with 'Not once': Frasa negatif mutlak ini memicu inversi. 'Did he forget' adalah struktur yang benar."
    },
    {
        question: "_______ questions, please contact the support team.",
        options: ["Should you have", "If you have had", "Had you", "Did you have"],
        answer: 0,
        explanation: "Inverted Conditional Type 1: 'Should you have...' setara dengan 'If you have...'. Ini adalah bentuk sopan/formal untuk instruksi."
    },
    {
        question: "Jupiter is the largest planet in the solar system, _______ more than twice as massive as all other planets combined.",
        options: ["is", "being", "it is", "that is"],
        answer: 1,
        explanation: "Participial Phrase: Kita membutuhkan frasa penjelas yang tidak memutus kalimat utama. 'Being...' berfungsi menjelaskan status Jupiter tanpa membuat run-on sentence."
    },
    {
        question: "I propose that the meeting _______ postponed until further notice.",
        options: ["is", "be", "to be", "will be"],
        answer: 1,
        explanation: "Subjunctive Passive: 'Propose' memicu subjunctive. Bentuk pasifnya adalah 'be + V3' (be postponed)."
    },
    {
        question: "Little _______ how much the decision would affect his future.",
        options: ["he realized", "did he realize", "he did realize", "realized he"],
        answer: 1,
        explanation: "Inversion with 'Little': Bermakna 'He did not realize much'. Di awal kalimat, wajib inversi: 'did he realize'."
    },
    {
        question: "_______ bacteria are invisible to the naked eye, they are essential to life.",
        options: ["Despite", "While", "However", "Nevertheless"],
        answer: 1,
        explanation: "Conjunction of Contrast: Kita butuh kata hubung yang diikuti kalimat lengkap (S+V) dan menunjukkan pertentangan. 'While' (sementara/walaupun) sangat tepat di sini."
    },
    {
        question: "The machinery _______ regularly to ensure safety.",
        options: ["must inspect", "must be inspected", "must inspecting", "must have inspected"],
        answer: 1,
        explanation: "Passive Voice with Modals: Mesin 'harus diperiksa'. Polanya: Modal + be + V3. 'Must be inspected'."
    },
    {
        question: "_______ in the atmosphere is the greenhouse effect.",
        options: ["What traps heat", "That traps heat", "Trapping heat", "Heat trapped"],
        answer: 0,
        explanation: "Noun Clause as Subject: Kita butuh subjek yang bermakna 'Sesuatu yang menjebak panas'. 'What traps heat' adalah noun clause yang berfungsi sebagai subjek kalimat."
    },
    {
        question: "Hardly had I stepped out of the house _______ it started to pour.",
        options: ["than", "when", "then", "after"],
        answer: 1,
        explanation: "Correlative Conjunction: Pasangan abadi 'Hardly' adalah 'when'. (Hardly... when...)."
    },
    {
        question: "_______ the sheer size of the universe, it is unlikely that we are alone.",
        options: ["Given", "Giving", "To give", "Gave"],
        answer: 0,
        explanation: "Prepositional Participle: 'Given' di sini berfungsi sebagai preposisi yang bermakna 'Considering' (Mengingat/Mempertimbangkan). Ini adalah bentuk baku untuk memulai kalimat premis."
    },
    {
        question: "Not for one moment _______ that he was lying.",
        options: ["I suspected", "did I suspect", "I did suspect", "suspected I"],
        answer: 1,
        explanation: "Negative Adverbial Inversion: Frasa 'Not for one moment' bersifat negatif dan diletakkan di awal kalimat. Ini memicu inversi: Auxiliary (did) + Subject (I) + Verb (suspect)."
    },
    {
        question: "The director recommends that the contract _______ immediately.",
        options: ["sign", "signs", "signed", "be signed"],
        answer: 3,
        explanation: "Subjunctive Passive: Kata 'recommends' memicu subjunctive mood. Polanya: 'that + subject + verb dasar (bare infinitive)'. Karena kontrak itu 'ditandatangani' (pasif), maka bentuknya adalah 'be + V3' (be signed)."
    },
    {
        question: "_______, the more difficult it is to break.",
        options: ["The old the habit", "The older the habit", "Older the habit", "The habit is older"],
        answer: 1,
        explanation: "Double Comparative: Pola 'The + comparative ..., the + comparative ...'. Bagian pertama harus paralel dengan bagian kedua. 'The older the habit (is), the more difficult...'."
    },
    {
        question: "It is strictly forbidden _______ the restricted area.",
        options: ["entering", "to enter", "enter", "entered"],
        answer: 1,
        explanation: "Infinitive as Subject Complement: Setelah adjektiva 'forbidden' dalam pola 'It is + adj', kita menggunakan 'to infinitive' (to enter) untuk menjelaskan tindakan yang dilarang tersebut."
    },
    {
        question: "_______ by the complexity of the problem, the student asked for help.",
        options: ["Confusing", "Confused", "To confuse", "Confuse"],
        answer: 1,
        explanation: "Past Participle (Passive Meaning): Siswa tersebut 'bingung' (merasa dibingungkan oleh masalah), bukan 'membingungkan'. Jadi gunakan V3 'Confused' (Reduksi dari 'Because he was confused...')."
    },
    {
        question: "Scarcely _______ the door when the phone rang.",
        options: ["he had opened", "had he opened", "did he open", "opened he"],
        answer: 1,
        explanation: "Inversion with 'Scarcely': Kata ini bermakna 'baru saja/hampir tidak'. Jika di awal kalimat, harus inversi Past Perfect: 'had he opened'."
    },
    {
        question: "The company’s revenue is higher than _______.",
        options: ["last year", "that of last year", "those of last year", "last year's one"],
        answer: 1,
        explanation: "Logical Comparison: Kita membandingkan 'revenue' (tunggal) tahun ini dengan 'revenue' tahun lalu. Gunakan 'that' sebagai kata ganti 'revenue'. 'That of last year'."
    },
    {
        question: "_______ he been a bit more careful, the accident could have been avoided.",
        options: ["Had", "If", "Should", "Were"],
        answer: 0,
        explanation: "Inverted Conditional Type 3: Ini adalah inversi dari 'If he had been...'. Kita menghilangkan 'If' dan memindahkan 'Had' ke depan."
    },
    {
        question: "Whatever _______, I will support you.",
        options: ["happens", "happen", "happening", "to happen"],
        answer: 0,
        explanation: "Noun Clause Subject: Dalam klausa 'Whatever happens', 'Whatever' dianggap sebagai subjek tunggal (singular), sehingga verb-nya 'happens'."
    },
    {
        question: "Rarely _______ anyone as dedicated as she is.",
        options: ["you meet", "do you meet", "you do meet", "meet you"],
        answer: 1,
        explanation: "Inversion with Negative Adverb: 'Rarely' di awal kalimat memicu inversi. Auxiliary 'do' harus mendahului subjek 'you'."
    },
    {
        question: "_______ to be the smartest student in the class, John always gets straight A's.",
        options: ["Considering", "Considered", "Consider", "To consider"],
        answer: 1,
        explanation: "Reduced Passive Clause: John 'dianggap' (passive) sebagai siswa terpintar. Maka gunakan V3 'Considered' (Reduksi dari 'Because he is considered...')."
    },
    {
        question: "It is essential that every applicant _______ the instructions carefully.",
        options: ["read", "reads", "reading", "to read"],
        answer: 0,
        explanation: "Subjunctive Mood: 'Essential' memicu subjunctive. Verb harus 'bare infinitive' (read) tanpa 's', meskipun subjeknya tunggal 'every applicant'."
    },
    {
        question: "_______ the heavy rain, the game was not cancelled.",
        options: ["Despite", "Although", "Even though", "However"],
        answer: 0,
        explanation: "Preposition: 'The heavy rain' adalah Noun Phrase. Kita butuh preposisi 'Despite'. ('Although' butuh S+V)."
    },
    {
        question: "Only after _______ the report did I realize my mistake.",
        options: ["submit", "submitting", "submitted", "submission"],
        answer: 1,
        explanation: "Preposition + Gerund: 'After' adalah preposisi di sini, jadi harus diikuti Gerund (V-ing). 'Only after submitting...'."
    },
    {
        question: "The manager asked that we _______ late for the meeting.",
        options: ["not be", "are not", "not to be", "won't be"],
        answer: 0,
        explanation: "Subjunctive Negative: Pola subjunctive negatif adalah 'not + bare infinitive'. Jadi 'not be', bukan 'are not' atau 'do not be'."
    },
    {
        question: "_______ giant squid is elusive, we know very little about its habits.",
        options: ["Because the", "The", "For the", "Since"],
        answer: 0,
        explanation: "Conjunction of Cause: Kita butuh kata hubung sebab-akibat yang lengkap. 'Because the...' menghubungkan klausa 'giant squid is elusive' dengan klausa utama."
    },
    {
        question: "Hardly _______ sat down when the doorbell rang.",
        options: ["I had", "had I", "did I", "have I"],
        answer: 1,
        explanation: "Correlative Inversion: Pasangan 'Hardly... when...'. Inversi Past Perfect diperlukan: 'had I'."
    },
    {
        question: "The ancient ruins, _______ in the jungle, were finally discovered.",
        options: ["hidden", "hiding", "hide", "to hide"],
        answer: 0,
        explanation: "Reduced Relative Clause (Passive): Reruntuhan itu 'tersembunyi' (passive state). 'Hidden' adalah V3 yang tepat (reduksi dari 'which were hidden')."
    },
    {
        question: "_______ gene therapy works is still a mystery to many.",
        options: ["That", "How", "What", "Which"],
        answer: 1,
        explanation: "Noun Clause as Subject: Kita butuh kata tanya yang menjelaskan 'cara/mekanisme'. 'How gene therapy works' (Bagaimana terapi gen bekerja) adalah subjek kalimat ini."
    },
    {
        question: "Under no circumstances _______ open the emergency exit.",
        options: ["you should", "should you", "you must", "must you"],
        answer: 1,
        explanation: "Negative Inversion: 'Under no circumstances' (jangan pernah) memicu inversi modal. 'Should you' atau 'must you' (tergantung opsi, di sini 'should you' lebih umum untuk instruksi prosedural/larangan sopan tapi tegas)."
    },
    {
        question: "_______ broken, the seal cannot be replaced.",
        options: ["Once", "While", "During", "That"],
        answer: 0,
        explanation: "Conjunction with Past Participle: 'Once (it is) broken...'. Kata 'Once' sangat lazim digunakan dengan participle untuk menyatakan kondisi 'setelah sesuatu terjadi'."
    },
    {
        question: "The more you practice, _______ you will become.",
        options: ["the skilled", "the more skilled", "more skilled", "most skilled"],
        answer: 1,
        explanation: "Double Comparative: Pola 'The more..., the more...'. Kita butuh 'the' diikuti bentuk komparatif adjective 'skilled' -> 'the more skilled'."
    },
    {
        question: "_______ I known the truth, I would have acted differently.",
        options: ["Had", "If", "Have", "Should"],
        answer: 0,
        explanation: "Inverted Conditional Type 3: 'Had I known...' adalah bentuk inversi dari 'If I had known...'."
    },
    {
        question: "_______ regarded as a failure, the project taught us valuable lessons.",
        options: ["Though", "Despite", "However", "Nevertheless"],
        answer: 0,
        explanation: "Reduced Clause Conjunction: 'Though (it was) regarded...'. Kita butuh conjunction yang bisa diikuti participle. 'Despite' harus diikuti noun/gerund (Despite being regarded...)."
    },
    {
        question: "Little _______ that he was about to win the lottery.",
        options: ["he knew", "did he know", "knew he", "he did know"],
        answer: 1,
        explanation: "Inversion with 'Little': Bermakna 'Dia tidak tahu sama sekali'. Wajib inversi: 'did he know'."
    },
    {
        question: "_______ to the party, she bought a new dress.",
        options: ["Invited", "Having invited", "Inviting", "To invite"],
        answer: 0,
        explanation: "Reduced Passive Clause of Reason: Dia 'diundang' (passive). Jadi gunakan V3 'Invited' (reduksi dari 'Because she was invited...')."
    },
    {
        question: "It is vital that the evidence _______ untouched.",
        options: ["remain", "remains", "remained", "remaining"],
        answer: 0,
        explanation: "Subjunctive Mood: 'Vital' memicu subjunctive. Verb harus 'bare infinitive' (remain), tanpa 's'."
    },
    {
        question: "No sooner had the rain stopped _______ the sun came out.",
        options: ["than", "when", "then", "as"],
        answer: 0,
        explanation: "Correlative Conjunction: Pasangan abadi 'No sooner' adalah 'than'. (Ingat: No sooner... than)."
    },
    {
        question: "_______ of the two candidates is suitable for the job.",
        options: ["Neither", "None", "No one", "Not one"],
        answer: 0,
        explanation: "Quantifier: Untuk dua orang, yang bermakna negatif (tidak keduanya) adalah 'Neither'."
    },
    {
        question: "The phenomena _______ by the scientists were extraordinary.",
        options: ["observe", "observed", "observing", "observation"],
        answer: 1,
        explanation: "Past Participle (Passive): Fenomena tersebut 'diamati' (passive). 'Observed' adalah reduksi dari 'which were observed'."
    },
    {
        question: "Not until tomorrow _______ the results.",
        options: ["we will know", "will we know", "we know", "do we know"],
        answer: 1,
        explanation: "Time Phrase Inversion: 'Not until tomorrow' di awal kalimat memicu inversi Future Tense: 'will we know'."
    },
    {
        question: "_______ rapid inflation, the currency lost its value.",
        options: ["Because", "Due to", "Since", "As"],
        answer: 1,
        explanation: "Preposition: 'Rapid inflation' adalah Noun Phrase. Kita butuh 'Due to'. ('Because', 'Since', 'As' butuh S+V)."
    },
    {
        question: "Had it not been for the alarm, we _______ overslept.",
        options: ["would have", "will have", "would", "had"],
        answer: 0,
        explanation: "Conditional Type 3 Result: Bagian 'result' dari pengandaian masa lalu butuh 'would have + V3'. Di sini 'overslept' adalah V3, jadi tinggal 'would have'."
    },
    {
        question: "_______ creates a harmonious atmosphere.",
        options: ["Listening to music", "To listen music", "Music listening", "Listen to music"],
        answer: 0,
        explanation: "Gerund as Subject: 'Listening to music' adalah frasa Gerund yang berfungsi sebagai subjek tunggal."
    },
    {
        question: "I suggest that she _______ a doctor immediately.",
        options: ["sees", "see", "saw", "seen"],
        answer: 1,
        explanation: "Subjunctive Mood: 'Suggest' memicu subjunctive. Verb 'see' harus dalam bentuk dasar (bare infinitive)."
    },
    {
        question: "_______ finding a solution, he gave up.",
        options: ["Instead of", "Because of", "In spite", "Rather"],
        answer: 0,
        explanation: "Prepositional Logic: Konteks kalimat menunjukkan dia menyerah 'alih-alih' menemukan solusi. 'Instead of' adalah yang paling tepat."
    },
    {
        question: "Only if you study hard _______ pass the exam.",
        options: ["you will", "will you", "you can", "can you"],
        answer: 1,
        explanation: "Inversion with 'Only if': Memicu inversi pada klausa utama. 'Will you' adalah struktur yang benar."
    },
    {
        question: "The population of China is larger than _______.",
        options: ["India", "that of India", "those of India", "India's one"],
        answer: 1,
        explanation: "Logical Comparison: Membandingkan 'population' (tunggal) China dengan 'population' India. Gunakan 'that of India'."
    },
    {
        question: "_______, the document was sent to the archives.",
        options: ["Signing", "Signed", "Having been signed", "To sign"],
        answer: 2,
        explanation: "Perfect Passive Participle: Menekankan urutan waktu (sudah ditandatangani dulu, baru dikirim) dan pasif. 'Having been signed' adalah bentuk paling presisi."
    },
    {
        question: "Scarcely _______ the news when everyone cheered.",
        options: ["announced he", "did he announce", "had he announced", "he announced"],
        answer: 2,
        explanation: "Inversion Past Perfect: 'Scarcely' biasanya dipasangkan dengan Past Perfect (had + V3) untuk menunjukkan satu kejadian menyusul kejadian lain dengan cepat."
    },
    {
        question: "_______ interesting, the book was also educational.",
        options: ["Besides being", "Beside being", "Although being", "While being"],
        answer: 0,
        explanation: "Preposition: 'Besides' bermakna 'In addition to' (Selain ...). 'Beside' bermakna 'di sebelah'. Kita butuh 'Besides being...'."
    },
    {
        question: "We requested that the heater _______ turned on.",
        options: ["is", "was", "be", "were"],
        answer: 2,
        explanation: "Subjunctive Passive: 'Requested' memicu subjunctive. Bentuk pasif dasarnya adalah 'be + V3'."
    },
    {
        question: "Never _______ such a beautiful sunset.",
        options: ["I have seen", "have I seen", "did I see", "saw I"],
        answer: 1,
        explanation: "Inversion with Negative Adverb: 'Never' di awal kalimat memicu inversi present perfect: 'have I seen'."
    },
    {
        question: "_______ caught in the traffic, he missed the flight.",
        options: ["Getting", "Got", "To get", "Having"],
        answer: 0,
        explanation: "Participle Phrase of Cause: 'Getting caught...' (Karena terjebak...). Ini adalah bentuk umum (Get + V3) yang di-gerund-kan untuk menjelaskan sebab."
    },
    {
        question: "The laws of physics apply to everyone, _______ they are rich or poor.",
        options: ["whether", "if", "that", "despite"],
        answer: 0,
        explanation: "Correlative Conjunction: 'Whether... or...' digunakan untuk menunjukkan bahwa kondisi (kaya/miskin) tidak mempengaruhi hasil."
    },
    {
        question: "Not only _______ the championship, but he also broke the world record.",
        options: ["he won", "did he win", "won he", "he did win"],
        answer: 1,
        explanation: "Inversion with 'Not only': Memicu inversi auxiliary 'did' + subject 'he' + verb 'win'."
    },
    {
        question: "The higher the demand, _______ the price.",
        options: ["higher", "the higher", "highest", "the highest"],
        answer: 1,
        explanation: "Double Comparative: 'The higher..., the higher...'. Harus paralel menggunakan 'the' + comparative."
    },
    {
        question: "_______ objection to the proposal, the meeting continued.",
        options: ["There being no", "Because no", "There is no", "With no"],
        answer: 0,
        explanation: "Absolute Phrase: 'There being no objection' adalah frasa absolut yang sangat formal untuk menyatakan 'Karena tidak ada keberatan'. Pilihan D ('With no objection') juga mungkin secara informal, tapi A adalah struktur gramatikal klasik untuk konteks rapat resmi dalam tes tertulis."
    },
    {
        question: "It was _______ who called you yesterday.",
        options: ["I", "me", "my", "mine"],
        answer: 0,
        explanation: "Subject Complement: Dalam tata bahasa formal (seperti TOEFL), setelah to be (was/is), kita menggunakan Subject Pronoun (I, He, She), bukan Object Pronoun (me, him, her). 'It was I' adalah bentuk yang benar secara preskriptif."
    },
    {
        question: "_______ the sheer magnitude of the earthquake, the rescue team was surprised by the low number of casualties.",
        options: ["Given", "To give", "Giving", "Gave"],
        answer: 0,
        explanation: "Prepositional Participle: 'Given' di sini berfungsi sebagai preposisi yang bermakna 'Considering' (Mengingat/Mempertimbangkan fakta tersebut). Pola ini sangat umum dalam bahasa Inggris formal."
    },
    {
        question: "Not until the investigation is complete _______ the full details be released.",
        options: ["will", "the police will", "will the police", "to"],
        answer: 0,
        explanation: "Inversion with 'Not until': Frasa 'Not until...' di awal kalimat memicu inversi pada klausa utama (induk kalimat). Subject dan Auxiliary dibalik. Di sini, subjeknya adalah 'the full details' (passive), jadi 'will the full details be released'. Opsi A ('will') adalah auxiliary yang tepat untuk melengkapi struktur inversi tersebut."
    },
    {
        question: "The professor, along with his students, _______ attending the conference.",
        options: ["are", "is", "were", "have been"],
        answer: 1,
        explanation: "Subject-Verb Agreement: Frasa 'along with', 'together with', atau 'as well as' tidak mengubah jumlah subjek utama. Subjeknya tetap 'The professor' (tunggal), jadi verb-nya 'is'."
    },
    {
        question: "_______ a successful lawyer, she decided to pursue a career in painting.",
        options: ["Despite", "Although", "Having been", "To be"],
        answer: 2,
        explanation: "Perfect Participle (Active): Menunjukkan aksi yang sudah selesai sebelum aksi utama. 'Having been a successful lawyer' bermakna 'After she had been...'. Ini menjelaskan latar belakang keputusannya."
    },
    {
        question: "It is mandatory that every visitor _______ a visitor badge.",
        options: ["wears", "wear", "wearing", "to wear"],
        answer: 1,
        explanation: "Subjunctive Mood: Kata 'mandatory' memicu subjunctive. Verb harus dalam bentuk dasar (bare infinitive) yaitu 'wear', tanpa akhiran 's' meskipun subjeknya 'every visitor'."
    },
    {
        question: "_______ little rain falls in the desert, few plants can survive there.",
        options: ["Since", "Because of", "Due to", "For"],
        answer: 0,
        explanation: "Conjunction of Cause: Kita butuh kata hubung yang diikuti oleh klausa (Subject + Verb: 'little rain falls'). 'Since' atau 'Because' adalah pilihan tepat. 'Because of' dan 'Due to' harus diikuti Noun Phrase."
    },
    {
        question: "Only by practicing every day _______ master the violin.",
        options: ["you can", "can you", "you will", "will you"],
        answer: 1,
        explanation: "Inversion with 'Only by': Keterangan cara yang diawali 'Only' di depan kalimat memicu inversi. Modal 'can' harus diletakkan sebelum subjek 'you'."
    },
    {
        question: "The machinery, _______ expensive to maintain, was replaced.",
        options: ["prove", "proving", "proved", "proven"],
        answer: 1,
        explanation: "Reduced Adjective Clause (Active): Mesin tersebut 'terbukti' (proving) mahal. Asalnya: 'which proved expensive'. Dalam reduksi aktif, kita menggunakan V-ing."
    },
    {
        question: "Had I known it was your birthday, I _______ you a gift.",
        options: ["would buy", "bought", "would have bought", "will have bought"],
        answer: 2,
        explanation: "Conditional Type 3 (Past Unreal): Pengandaian masa lalu yang tidak terjadi. Rumusnya: If + Past Perfect, S + Would have + V3. 'Had I known' adalah inversi dari 'If I had known'."
    },
    {
        question: "_______ the outcome, we must proceed with the plan.",
        options: ["Regardless of", "Regarding", "Regards", "In regard"],
        answer: 0,
        explanation: "Prepositional Phrase: 'Regardless of' bermakna 'Tanpa mempedulikan/Terlepas dari'. Ini cocok dengan konteks kalimat."
    },
    {
        question: "Rarely _______ such a dedicated employee.",
        options: ["we find", "do we find", "find we", "we have found"],
        answer: 1,
        explanation: "Inversion with Negative Adverb: 'Rarely' di awal kalimat memicu inversi (Auxiliary + S + V). 'Do we find' adalah struktur yang benar."
    },
    {
        question: "The instructions require that the form _______ in black ink.",
        options: ["is filled", "be filled", "fills", "filled"],
        answer: 1,
        explanation: "Subjunctive Passive: 'Require' memicu subjunctive. Bentuk pasifnya adalah 'be + V3' (be filled)."
    },
    {
        question: "_______ of the danger, he entered the burning building.",
        options: ["Unaware", "Unawares", "Unawareness", "Not awareing"],
        answer: 0,
        explanation: "Adjective Phrase as Modifier: 'Unaware of the danger' menjelaskan subjek 'he'. Ini adalah bentuk reduksi dari 'Because he was unaware...'."
    },
    {
        question: "No sooner had I started the presentation _______ the projector failed.",
        options: ["when", "than", "then", "after"],
        answer: 1,
        explanation: "Correlative Conjunction: Pasangan 'No sooner' adalah 'than'. (Ingat: No sooner... than, Scarcely... when)."
    },
    {
        question: "The solution to the problem is _______ complicated than we thought.",
        options: ["much more", "many more", "very more", "too more"],
        answer: 0,
        explanation: "Degree Modifier: Untuk memperkuat komparatif (more complicated), kita menggunakan 'much', 'far', atau 'way'. Kita tidak bisa menggunakan 'very' atau 'too' langsung di depan komparatif."
    },
    {
        question: "_______ is no excuse for breaking the law.",
        options: ["Ignorance", "To ignore", "Ignoring", "Ignore"],
        answer: 0,
        explanation: "Noun as Subject: Kita butuh kata benda abstrak sebagai subjek. 'Ignorance' (Ketidaktahuan) adalah noun yang tepat. Gerund 'Ignoring' (Mengabaikan) kurang tepat secara makna dalam konteks idiom hukum ini ('Ignorance of the law')."
    },
    {
        question: "_______, the experiment yielded interesting results.",
        options: ["Though flawed", "Despite flawed", "Although flawing", "Flaw"],
        answer: 0,
        explanation: "Reduced Clause: 'Though (it was) flawed...'. Kita butuh conjunction + participle/adjective. 'Despite' harus diikuti noun (Despite the flaws)."
    },
    {
        question: "So loud _______ that the neighbors called the police.",
        options: ["was the music", "the music was", "is the music", "the music is"],
        answer: 0,
        explanation: "Inversion with 'So + Adjective': Pola 'So [adj] be [subject] that...' digunakan untuk penekanan. 'So loud was the music...'."
    },
    {
        question: "_______ to catch the bus, he ran as fast as he could.",
        options: ["Hoping", "Hoped", "To hope", "Hope"],
        answer: 0,
        explanation: "Present Participle Phrase: Menjelaskan alasan/tindakan bersamaan subjek. 'Hoping' (Berharap) adalah bentuk aktif."
    },
    {
        question: "It is time the government _______ action on climate change.",
        options: ["take", "takes", "took", "taken"],
        answer: 2,
        explanation: "Subjunctive with 'It is time': Ungkapan 'It is time (that)...' diikuti oleh Past Tense untuk menunjukkan urgensi saat ini (unreal present). Jadi 'took'."
    },
    {
        question: "_______ gene mutation occurs is a subject of ongoing research.",
        options: ["How", "That", "Which", "Because"],
        answer: 0,
        explanation: "Noun Clause as Subject: Kita butuh kata tanya yang menjelaskan proses. 'How gene mutation occurs' (Bagaimana mutasi gen terjadi) adalah subjek kalimat."
    },
    {
        question: "Never before _______ experienced such hospitality.",
        options: ["I have", "have I", "did I", "had I"],
        answer: 1,
        explanation: "Inversion with 'Never': Memicu inversi. 'Have I experienced' (Present Perfect) paling cocok untuk menyatakan pengalaman hidup sampai sekarang."
    },
    {
        question: "The more details you provide, _______ for us to help you.",
        options: ["the easier it is", "easier it is", "the easy it is", "it is easier"],
        answer: 0,
        explanation: "Double Comparative: 'The more..., the easier...'. Pola paralel dengan 'the'."
    },
    {
        question: "_______ objection from the board, the proposal was approved.",
        options: ["There being no", "Because no", "With not", "Since not"],
        answer: 0,
        explanation: "Absolute Phrase: Struktur formal 'There being no...' digunakan untuk menyatakan alasan ketiadaan sesuatu."
    },
    {
        question: "_______ classified as a reptile, the animal regulates its own body temperature.",
        options: ["Although", "Despite", "However", "In spite"],
        answer: 0,
        explanation: "Reduced Clause Conjunction: 'Although (it is) classified...'. Butuh conjunction kontras."
    },
    {
        question: "Under no circumstances _______ the password be shared.",
        options: ["should", "can", "must", "will"],
        answer: 0,
        explanation: "Inversion/Modal Usage: 'Should' adalah modal yang paling tepat untuk instruksi/larangan keras dalam konteks 'Under no circumstances'."
    },
    {
        question: "_______ finding the evidence, the detective closed the case.",
        options: ["Upon", "When", "While", "Since"],
        answer: 0,
        explanation: "Preposition + Gerund: 'Upon' bermakna 'Segera setelah'. 'Upon finding' = As soon as he found."
    },
    {
        question: "The director suggested that the scene _______ cut from the final film.",
        options: ["is", "was", "be", "were"],
        answer: 2,
        explanation: "Subjunctive Passive: 'Suggested' memicu subjunctive. Pasif: 'be + V3' (be cut)."
    },
    {
        question: "Scarcely _______ the room when the lights went out.",
        options: ["had we entered", "we had entered", "did we enter", "we entered"],
        answer: 0,
        explanation: "Inversion Past Perfect: 'Scarcely' + Had + S + V3. 'Had we entered'."
    },
    {
        question: "_______ of the two options is ideal.",
        options: ["Neither", "None", "No one", "Not one"],
        answer: 0,
        explanation: "Quantifier: 'Neither' untuk dua pilihan."
    },
    {
        question: "Generally, the climate in the south is warmer than _______ in the north.",
        options: ["that", "those", "one", "it"],
        answer: 0,
        explanation: "Demonstrative Pronoun: Menggantikan 'the climate' (tunggal). Gunakan 'that'."
    },
    {
        question: "_______ by the wind, the tree fell onto the road.",
        options: ["Blown", "Blowing", "Blew", "To blow"],
        answer: 0,
        explanation: "Past Participle (Passive): Pohon itu 'tertiup' (blown), bukan meniup."
    },
    {
        question: "Not only _______ the deadline, but they also exceeded expectations.",
        options: ["did they meet", "they met", "met they", "they did meet"],
        answer: 0,
        explanation: "Inversion with 'Not only': Auxiliary 'did' mendahului subjek 'they'."
    },
    {
        question: "Whatever _______, we will remain united.",
        options: ["occurs", "occur", "occurring", "to occur"],
        answer: 0,
        explanation: "Noun Clause Subject: 'Whatever' dianggap tunggal -> 'occurs'."
    },
    {
        question: "Had I known you were coming, I _______ a cake.",
        options: ["would have baked", "will bake", "would bake", "baked"],
        answer: 0,
        explanation: "Conditional Type 3 Result: Butuh 'would have + V3'."
    },
    {
        question: "_______ interesting, the documentary was also informative.",
        options: ["Besides being", "Beside being", "However", "Yet"],
        answer: 0,
        explanation: "Preposition: 'Besides being...' (Selain menarik...)."
    },
    {
        question: "It is vital that the patient _______ his medication regularly.",
        options: ["take", "takes", "taking", "took"],
        answer: 0,
        explanation: "Subjunctive: 'Vital' memicu bare infinitive 'take'."
    },
    {
        question: "_______ the traffic was heavy, we arrived on time.",
        options: ["Although", "Despite", "In spite of", "However"],
        answer: 0,
        explanation: "Conjunction: Diikuti klausa (Subject + Verb). 'Although' adalah pilihan yang benar. 'Despite' butuh noun."
    },
    {
        question: "Only if you hurry _______ catch the train.",
        options: ["will you", "you will", "can you", "you can"],
        answer: 0,
        explanation: "Inversion with 'Only if': 'Will you' (Future)."
    },
    {
        question: "The results of the study are distinct from _______ of previous research.",
        options: ["those", "that", "this", "these"],
        answer: 0,
        explanation: "Logical Comparison: Menggantikan 'results' (jamak). Gunakan 'those'."
    },
    {
        question: "_______, the manuscript was published.",
        options: ["Revised", "Having been revised", "Revising", "To revise"],
        answer: 1,
        explanation: "Perfect Passive Participle: Menunjukkan urutan (sudah direvisi dulu) dan pasif. 'Having been revised'."
    },
    {
        question: "Little _______ that he was being watched.",
        options: ["did he suspect", "he suspected", "suspected he", "was he suspected"],
        answer: 0,
        explanation: "Inversion with 'Little': 'Did he suspect'."
    },
    {
        question: "_______ to the conference, she prepared a presentation.",
        options: ["Invited", "Inviting", "To invite", "Having invited"],
        answer: 0,
        explanation: "Reduced Passive: 'Because she was invited' -> 'Invited'."
    },
    {
        question: "It is essential that the data _______ accurate.",
        options: ["be", "is", "was", "are"],
        answer: 0,
        explanation: "Subjunctive: 'Be' (bare infinitive dari to be)."
    },
    {
        question: "No sooner had the bell rung _______ the students left.",
        options: ["than", "when", "then", "after"],
        answer: 0,
        explanation: "Correlative: 'No sooner... than'."
    },
    {
        question: "_______ of the witnesses could identify the suspect.",
        options: ["None", "Neither", "Not one", "No one"],
        answer: 0,
        explanation: "Quantifier: 'None' biasanya digunakan untuk kelompok (lebih dari 2). Jika konteks jumlah tidak disebut, 'None' adalah asumsi umum untuk 'tak satu pun dari mereka'."
    },
    {
        question: "The artifacts _______ by the archaeologists were fragile.",
        options: ["discovered", "discovering", "discover", "discovery"],
        answer: 0,
        explanation: "Past Participle (Passive): 'Which were discovered' -> 'Discovered'."
    },
    {
        question: "Not until next week _______ the decision.",
        options: ["will we know", "we will know", "do we know", "we know"],
        answer: 0,
        explanation: "Time Inversion: 'Will we know'."
    },
    {
        question: "_______ the heavy workload, he managed to finish early.",
        options: ["Despite", "Although", "Even though", "As"],
        answer: 0,
        explanation: "Preposition: 'The heavy workload' adalah Noun Phrase -> 'Despite'."
    },
    {
        question: "Had it not been for the map, we _______ lost.",
        options: ["would have gotten", "will get", "would get", "got"],
        answer: 0,
        explanation: "Conditional Type 3 Result: 'Would have + V3'."
    },
    {
        question: "_______ the rising cost of living, many families are cutting back on expenses.",
        options: ["Because", "Since", "Due to", "For"],
        answer: 2,
        explanation: "Preposition vs Conjunction: 'The rising cost of living' adalah Frasa Kata Benda (Noun Phrase), bukan kalimat utuh. Oleh karena itu, kita memerlukan preposisi 'Due to'. 'Because', 'Since', dan 'For' (sebagai kata hubung) harus diikuti oleh Subject + Verb."
    },
    {
        question: "Not only _______ the project on time, but he also managed to save money.",
        options: ["he finished", "did he finish", "finished he", "he did finish"],
        answer: 1,
        explanation: "Inversion with 'Not only': Ketika kalimat dimulai dengan 'Not only', struktur kalimat pertama harus diinversi (Auxiliary + Subject + Verb). Jadi, 'did he finish'."
    },
    {
        question: "The number of students interested in the program _______ increased significantly.",
        options: ["have", "has", "are", "were"],
        answer: 1,
        explanation: "Subject-Verb Agreement: Perbedaan 'The number of' vs 'A number of'. 'The number of' (jumlah dari...) dianggap sebagai subjek TUNGGAL (singular), sehingga verb-nya 'has'. (Sebaliknya, 'A number of' dianggap jamak)."
    },
    {
        question: "It is crucial that the equipment _______ calibrated before every use.",
        options: ["is", "be", "was", "are"],
        answer: 1,
        explanation: "Subjunctive Passive: Kata 'crucial' memicu subjunctive mood. Bentuk pasifnya menggunakan 'be' dasar + V3 ('be calibrated'). Jangan terkecoh menggantinya dengan 'is' atau 'was'."
    },
    {
        question: "_______, the athlete was disqualified from the competition.",
        options: ["Having taken a banned substance", "Taking a banned substance", "To take a banned substance", "Taken a banned substance"],
        answer: 0,
        explanation: "Perfect Participle (Active): Menggunakan 'Having + V3' menekankan bahwa aksi (minum obat terlarang) terjadi *sebelum* aksi utama (didiskualifikasi). Ini memberikan urutan waktu yang jelas."
    },
    {
        question: "Only when the data is analyzed _______ the final report.",
        options: ["we can publish", "can we publish", "we publish", "publish we"],
        answer: 1,
        explanation: "Inversion with Time Clause: 'Only when...' di awal kalimat memicu inversi pada klausa utama. Modal 'can' harus diletakkan sebelum subjek 'we'."
    },
    {
        question: "The committee is comprised _______ ten members.",
        options: ["from", "of", "by", "in"],
        answer: 1,
        explanation: "Idiomatic Preposition: Frasa yang benar adalah 'comprised of' (terdiri dari). Alternatif lain adalah 'composed of' atau 'consists of', tapi 'comprised' pasangannya 'of'."
    },
    {
        question: "_______ had I left the house than it began to snow.",
        options: ["Scarcely", "Hardly", "No sooner", "Rarely"],
        answer: 2,
        explanation: "Correlative Conjunction: Perhatikan kata pasangannya di tengah kalimat, yaitu 'than'. Pasangan dari 'than' adalah 'No sooner'. (Scarcely/Hardly berpasangan dengan 'when')."
    },
    {
        question: "Neither the teacher nor the students _______ happy with the new schedule.",
        options: ["was", "were", "is", "has been"],
        answer: 1,
        explanation: "Subject-Verb Agreement with 'Nor': Dalam struktur 'Neither... nor...', verb mengikuti subjek yang *paling dekat* dengannya. 'Students' (jamak) lebih dekat ke verb daripada 'teacher', jadi gunakan 'were'."
    },
    {
        question: "The painting, _______ to be a forgery, was removed from the gallery.",
        options: ["suspecting", "suspected", "suspect", "to suspect"],
        answer: 1,
        explanation: "Reduced Relative Clause (Passive): Lukisan itu 'dicurigai' (passive). Bentuk lengkapnya 'which was suspected', diringkas menjadi V3 'suspected'."
    },
    {
        question: "_______ he is a brilliant scientist, he lacks communication skills.",
        options: ["Despite", "In spite of", "While", "Nevertheless"],
        answer: 2,
        explanation: "Conjunction of Contrast: Kita butuh kata hubung yang diikuti klausa lengkap (S+V: 'he is...'). 'While' (Walaupun/Sementara) adalah pilihan yang tepat. 'Despite/In spite of' butuh noun."
    },
    {
        question: "I would rather you _______ home now.",
        options: ["go", "went", "gone", "will go"],
        answer: 1,
        explanation: "Subjunctive with 'Would Rather': Jika subjek setelah 'would rather' berbeda (I vs You) dan keinginannya untuk saat ini/masa depan, gunakan Past Tense ('went')."
    },
    {
        question: "The higher the altitude, _______ the air becomes.",
        options: ["the thin", "thinner", "the thinner", "thinnest"],
        answer: 2,
        explanation: "Double Comparative: Pola 'The + comparative, the + comparative'. Jadi, 'The higher..., the thinner...'."
    },
    {
        question: "_______ objection was raised, the meeting proceeded.",
        options: ["Since no", "There being no", "Because not", "As no"],
        answer: 1,
        explanation: "Absolute Phrase: 'There being no objection' adalah struktur formal untuk menyatakan sebab ('Karena tidak ada keberatan') tanpa membentuk klausa terikat penuh."
    },
    {
        question: "Had I known about the traffic, I _______ a different route.",
        options: ["will take", "would take", "took", "would have taken"],
        answer: 3,
        explanation: "Conditional Type 3: Pengandaian masa lalu. Bagian result (akibat) harus menggunakan 'would have + V3'."
    },
    {
        question: "_______ capable of running at high speeds, the cheetah is the fastest land animal.",
        options: ["Be", "Being", "Is", "To be"],
        answer: 1,
        explanation: "Reduced Adverbial Clause of Cause: 'Because it is capable...' diringkas menjadi 'Being capable...'. Menjelaskan sifat subjek."
    },
    {
        question: "Little _______ that he had won the lottery.",
        options: ["did he know", "he knew", "knew he", "he did know"],
        answer: 0,
        explanation: "Inversion with 'Little': Bermakna negatif ('Dia tidak tahu sama sekali'). Wajib inversi: 'did he know'."
    },
    {
        question: "The manager, as well as his assistants, _______ working on the proposal.",
        options: ["is", "are", "have been", "were"],
        answer: 0,
        explanation: "Subject-Verb Agreement: Frasa 'as well as' tidak mengubah jumlah subjek utama. Subjeknya tetap 'The manager' (tunggal), jadi verb-nya 'is'."
    },
    {
        question: "It is essential that she _______ the truth.",
        options: ["tells", "tell", "told", "telling"],
        answer: 1,
        explanation: "Subjunctive Mood: 'Essential' memicu subjunctive. Verb harus bare infinitive 'tell', tanpa 's'."
    },
    {
        question: "_______ to the party, we decided to stay home.",
        options: ["Not invited", "Not inviting", "Not to invite", "Did not invite"],
        answer: 0,
        explanation: "Reduced Passive Clause: 'Because we were not invited...' diringkas menjadi 'Not invited'. Subjek 'we' adalah penerima aksi (pasif)."
    },
    {
        question: "Whatever _______, we must keep moving forward.",
        options: ["happen", "happens", "happening", "to happen"],
        answer: 1,
        explanation: "Noun Clause Subject: 'Whatever' sebagai subjek dianggap tunggal -> 'happens'."
    },
    {
        question: "_______ by the stunning view, the tourists stopped to take photos.",
        options: ["Mesmerized", "Mesmerizing", "To mesmerize", "Mesmerize"],
        answer: 0,
        explanation: "Past Participle (Passive): Turis 'terpesona' (passive state) oleh pemandangan. Gunakan V3 'Mesmerized'."
    },
    {
        question: "Rarely _______ a politician admit to a mistake.",
        options: ["you hear", "do you hear", "hear you", "you do hear"],
        answer: 1,
        explanation: "Inversion with Negative Adverb: 'Rarely' di awal kalimat memicu inversi. 'Do you hear'."
    },
    {
        question: "The phenomena _______ observed by the astronomers were unusual.",
        options: ["that was", "which were", "what was", "it was"],
        answer: 1,
        explanation: "Relative Pronoun Agreement: 'Phenomena' adalah bentuk JAMAK (plural) dari 'phenomenon'. Maka harus menggunakan 'which were'. 'That was' salah karena verb-nya tunggal."
    },
    {
        question: "Under no circumstances _______ the door remain open.",
        options: ["must", "should", "can", "need"],
        answer: 1,
        explanation: "Modal Inversion: 'Should' adalah modal yang paling tepat untuk instruksi/aturan keras. 'Must' juga bisa, tapi 'Should' lebih umum dalam konteks 'Under no circumstances' untuk menekankan kewajiban prosedur. (Jawabannya inversi: 'should the door'). Di opsi ini hanya ada modalnya, asumsikan struktur lanjutannya benar."
    },
    {
        question: "_______ finding a job, he moved to the city.",
        options: ["With the aim of", "Because", "Due to", "In order"],
        answer: 0,
        explanation: "Prepositional Phrase: 'With the aim of' diikuti Gerund (finding). 'Because' butuh S+V, 'In order' butuh 'to'."
    },
    {
        question: "The theory _______ by the scientist was revolutionary.",
        options: ["propose", "proposed", "proposing", "proposal"],
        answer: 1,
        explanation: "Past Participle (Passive): Teori yang 'diajukan' (proposed). Reduksi dari 'which was proposed'."
    },
    {
        question: "Not until the end of the movie _______ who the killer was.",
        options: ["we found out", "did we find out", "found we out", "we did find out"],
        answer: 1,
        explanation: "Inversion with 'Not until': Memicu inversi pada klausa utama. 'Did we find out'."
    },
    {
        question: "_______ of the two students has completed the assignment.",
        options: ["Neither", "None", "Both", "All"],
        answer: 0,
        explanation: "Subject-Verb Agreement & Quantifier: Verb-nya adalah 'has' (tunggal). 'Both' dan 'All' butuh verb jamak. Antara 'Neither' dan 'None', untuk *dua* orang gunakan 'Neither'."
    },
    {
        question: "Generally, the behavior of wolves is more complex than _______ of dogs.",
        options: ["that", "those", "this", "these"],
        answer: 0,
        explanation: "Demonstrative Pronoun: Menggantikan 'the behavior' (tunggal). Gunakan 'that'."
    },
    {
        question: "_______, the car broke down.",
        options: ["Driven for miles", "Having been driven for miles", "Driving for miles", "To drive for miles"],
        answer: 1,
        explanation: "Perfect Passive Participle: Mobil itu 'telah dikendarai' (pasif + lampau) sebelum mogok. 'Having been driven' adalah bentuk yang paling presisi secara gramatikal."
    },
    {
        question: "It is important that he _______ not be late.",
        options: ["is", "does", "will", "(blank)"],
        answer: 3,
        explanation: "Subjunctive Negative: Strukturnya 'that he not be late'. Kata 'not' langsung diikuti verb dasar (be). Dalam opsi pilihan ganda, kadang opsinya adalah 'kosong' (jika struktur kalimat di soal sudah ada 'not be'), atau dalam kasus ini maksudnya verb bantunya hilang. *Koreksi*: Jika soalnya '...that he ____ late', jawabannya 'not be'. Jika soal tertulis '...that he ____ not be late', maka jawabannya adalah 'kosong' atau 'should' (British). Di sini mari asumsikan opsinya mencari verb bantu. Subjunctive TIDAK pakai auxiliary do/does. Jadi jawabannya bisa dianggap 'kosong' atau dalam tes tertulis seringkali opsinya adalah 'should' (optional). Namun, jika dipaksa memilih auxiliary, subjunctive murni tidak memakainya. Mari kita ganti opsi yang lebih jelas. *Revisi Soal*: 'It is important that he _______ late.' -> Options: 'not be', 'is not', 'not to be', 'won't be'. Answer: 'not be'."
    },
    {
        question: "Revised Question: It is important that he _______ late.",
        options: ["not be", "is not", "won't be", "doesn't be"],
        answer: 0,
        explanation: "Subjunctive Negative: Bentuk negatif subjunctive adalah 'not + bare infinitive'. Jadi 'not be'."
    },
    {
        question: "_______ the bad weather, the flight was delayed.",
        options: ["Because", "Since", "Owing to", "For"],
        answer: 2,
        explanation: "Preposition: 'The bad weather' adalah Noun Phrase. 'Owing to' (atau Due to) adalah preposisi. Yang lain adalah conjunction."
    },
    {
        question: "Only by working hard _______ achieve success.",
        options: ["you can", "can you", "you will", "will you"],
        answer: 1,
        explanation: "Inversion with 'Only by': 'Can you' (kemampuan/possibility)."
    },
    {
        question: "The ancient city, _______ in the desert, is a popular tourist destination.",
        options: ["locating", "located", "locate", "location"],
        answer: 1,
        explanation: "Reduced Passive: Kota itu 'terletak' (located). Reduksi dari 'which is located'."
    },
    {
        question: "Scarcely _______ the book when he fell asleep.",
        options: ["he read", "had he read", "did he read", "read he"],
        answer: 1,
        explanation: "Inversion Past Perfect: 'Scarcely' + had + S + V3. 'Had he read'."
    },
    {
        question: "_______ gene editing is ethical is a matter of debate.",
        options: ["That", "Whether", "If", "What"],
        answer: 1,
        explanation: "Noun Clause Subject: Karena ini adalah masalah perdebatan (debate), ada unsur ketidakpastian/pilihan. 'Whether' (Apakah...) lebih tepat daripada 'That' (Bahwa...)."
    },
    {
        question: "Never _______ such a rude person.",
        options: ["I have met", "have I met", "did I meet", "met I"],
        answer: 1,
        explanation: "Inversion with 'Never': 'Have I met'."
    },
    {
        question: "The more you study, _______ you will learn.",
        options: ["the more", "more", "most", "the most"],
        answer: 0,
        explanation: "Double Comparative: 'The more..., the more...'."
    },
    {
        question: "_______ of the evidence suggests that he is guilty.",
        options: ["Much", "Many", "Few", "Several"],
        answer: 0,
        explanation: "Quantifier: 'Evidence' adalah uncountable noun (tidak bisa dihitung). Gunakan 'Much'. ('Many', 'Few', 'Several' untuk countable)."
    },
    {
        question: "_______ tired, he went to bed early.",
        options: ["Feeling", "Felt", "To feel", "Feel"],
        answer: 0,
        explanation: "Present Participle (Active): Dia 'merasa' lelah. Gunakan V-ing 'Feeling' (Reduksi dari 'Because he was feeling...')."
    },
    {
        question: "Had it not been for your help, I _______ failed.",
        options: ["would have", "will have", "would", "had"],
        answer: 0,
        explanation: "Conditional Type 3 Result: 'Would have' (+ V3 failed)."
    },
    {
        question: "_______ interesting, the lecture was also long.",
        options: ["While", "Because", "Since", "As"],
        answer: 0,
        explanation: "Conjunction of Contrast (Reduced): 'While (it was) interesting...' (Meskipun menarik...). Menunjukkan kontras dengan 'long' (membosankan/lama)."
    },
    {
        question: "It is vital that the instructions _______ followed precisely.",
        options: ["are", "be", "were", "will be"],
        answer: 1,
        explanation: "Subjunctive Passive: 'Be + V3' (be followed)."
    },
    {
        question: "No sooner had we arrived _______ it started to rain.",
        options: ["than", "when", "then", "after"],
        answer: 0,
        explanation: "Correlative: 'No sooner... than'."
    },
    {
        question: "The species, _______ distinct from its relatives, is endangered.",
        options: ["though", "because", "due to", "since"],
        answer: 0,
        explanation: "Conjunction in Reduced Phrase: 'Though (it is) distinct...'. Menambahkan informasi kontras/sisipan."
    },
    {
        question: "_______ rapid population growth, resources are scarce.",
        options: ["Because of", "Because", "Since", "As"],
        answer: 0,
        explanation: "Preposition: 'Rapid population growth' adalah Noun Phrase -> 'Because of'."
    },
    {
        question: "The director required that everyone _______ the meeting.",
        options: ["attend", "attends", "attending", "attended"],
        answer: 0,
        explanation: "Subjunctive: 'Require' memicu bare infinitive 'attend'."
    },
    {
        question: "_______ caught in the storm, the ship returned to port.",
        options: ["Getting", "Having been", "To get", "Get"],
        answer: 1,
        explanation: "Perfect Passive Participle: Kapal 'telah terjebak' (pasif + lampau) sebelum kembali. 'Having been caught' paling tepat menjelaskan sebab dan urutan."
    },
    {
        question: "Hardly _______ started speaking when the microphone failed.",
        options: ["he had", "had he", "did he", "he did"],
        answer: 1,
        explanation: "Inversion: 'Hardly' + had + S. 'Had he'."
    }
];