const questionsSource = [
    // --- LEVEL: BEGINNER (20 Soal) ---
    // Fokus: Simple Present, Present Continuous, Simple Past, Simple Future

    {
        question: "I ______ breakfast every morning at 7 AM.",
        options: ["eat", "eating", "eats", "ate"],
        answer: 0,
        explanation: "Simple Present Tense"
    },
    {
        question: "She ______ to school yesterday.",
        options: ["go", "goes", "went", "gone"],
        answer: 2,
        explanation: "Simple Past Tense"
    },
    {
        question: "Listen! The baby ______.",
        options: ["cries", "cried", "is crying", "are crying"],
        answer: 2,
        explanation: "Present Continuous Tense"
    },
    {
        question: "We ______ visit our grandmother next week.",
        options: ["will", "did", "are", "have"],
        answer: 0,
        explanation: "Simple Future Tense"
    },
    {
        question: "He ______ like spicy food.",
        options: ["don't", "doesn't", "isn't", "didn't"],
        answer: 1,
        explanation: "Simple Present Tense"
    },
    {
        question: "They ______ football when it started to rain.",
        options: ["play", "played", "were playing", "are playing"],
        answer: 2,
        explanation: "Past Continuous Tense"
    },
    {
        question: "I ______ seen that movie before.",
        options: ["have", "has", "had", "am"],
        answer: 0,
        explanation: "Present Perfect Tense"
    },
    {
        question: "______ you happy with the result?",
        options: ["Do", "Did", "Are", "Will"],
        answer: 2,
        explanation: "Simple Present Tense (Nominal)"
    },
    {
        question: "My father ______ coffee right now.",
        options: ["drinks", "drank", "is drinking", "drink"],
        answer: 2,
        explanation: "Present Continuous Tense"
    },
    {
        question: "We ______ to Paris last year.",
        options: ["fly", "flew", "flown", "flying"],
        answer: 1,
        explanation: "Simple Past Tense"
    },
    {
        question: "The sun ______ in the east.",
        options: ["rise", "rises", "rising", "rose"],
        answer: 1,
        explanation: "Simple Present Tense"
    },
    {
        question: "I ______ call you later.",
        options: ["will", "am", "do", "have"],
        answer: 0,
        explanation: "Simple Future Tense"
    },
    {
        question: "She ______ a letter when I came.",
        options: ["wrote", "is writing", "was writing", "writes"],
        answer: 2,
        explanation: "Past Continuous Tense"
    },
    {
        question: "They ______ football every Sunday.",
        options: ["play", "plays", "playing", "played"],
        answer: 0,
        explanation: "Simple Present Tense"
    },
    {
        question: "I ______ my homework yet.",
        options: ["didn't finish", "haven't finished", "don't finish", "won't finish"],
        answer: 1,
        explanation: "Present Perfect Tense"
    },
    {
        question: "______ she go to the party last night?",
        options: ["Do", "Does", "Did", "Is"],
        answer: 2,
        explanation: "Simple Past Tense"
    },
    {
        question: "Look at the clouds! It ______ rain.",
        options: ["is going to", "will", "shall", "wants"],
        answer: 0,
        explanation: "Simple Future Tense (Be going to)"
    },
    {
        question: "Water ______ at 100 degrees Celsius.",
        options: ["boil", "boils", "boiling", "boiled"],
        answer: 1,
        explanation: "Simple Present Tense"
    },
    {
        question: "We ______ watching TV at the moment.",
        options: ["is", "am", "are", "be"],
        answer: 2,
        explanation: "Present Continuous Tense"
    },
    {
        question: "He ______ buy a new car next month.",
        options: ["is", "will", "did", "does"],
        answer: 1,
        explanation: "Simple Future Tense"
    },

    // --- LEVEL: INTERMEDIATE (30 Soal) ---
    // Fokus: Mix All 12 Tenses (termasuk Perfect, Perfect Continuous, Future Forms)

    {
        question: "I ______ here for ten years.",
        options: ["live", "am living", "have lived", "lived"],
        answer: 2,
        explanation: "Present Perfect Tense"
    },
    {
        question: "By this time tomorrow, I ______ to London.",
        options: ["will fly", "will be flying", "fly", "flew"],
        answer: 1,
        explanation: "Future Continuous Tense"
    },
    {
        question: "She ______ cooking when the phone rang.",
        options: ["finished", "has finished", "had finished", "finishes"],
        answer: 2,
        explanation: "Past Perfect Tense"
    },
    {
        question: "We ______ for three hours before the bus finally arrived.",
        options: ["have waited", "had been waiting", "waited", "were waiting"],
        answer: 1,
        explanation: "Past Perfect Continuous Tense"
    },
    {
        question: "At 8 PM tonight, they ______ dinner.",
        options: ["will have", "will be having", "have", "had"],
        answer: 1,
        explanation: "Future Continuous Tense"
    },
    {
        question: "He ______ tired because he has been working all day.",
        options: ["is", "was", "were", "has been"],
        answer: 0,
        explanation: "Simple Present Tense (Effect) & Present Perfect Continuous (Cause)"
    },
    {
        question: "By the end of this year, she ______ her degree.",
        options: ["will finish", "will have finished", "finishes", "has finished"],
        answer: 1,
        explanation: "Future Perfect Tense"
    },
    {
        question: "I ______ waiting for you since 8 o'clock.",
        options: ["am", "was", "have been", "had been"],
        answer: 2,
        explanation: "Present Perfect Continuous Tense"
    },
    {
        question: "When I arrived at the station, the train ______.",
        options: ["left", "has left", "had left", "leaves"],
        answer: 2,
        explanation: "Past Perfect Tense"
    },
    {
        question: "Next year, my parents ______ for 25 years.",
        options: ["are married", "will have been married", "have been married", "will marry"],
        answer: 1,
        explanation: "Future Perfect Tense"
    },
    {
        question: "While I ______ down the street, I met an old friend.",
        options: ["walked", "was walking", "have walked", "am walking"],
        answer: 1,
        explanation: "Past Continuous Tense"
    },
    {
        question: "They ______ the project by next Monday.",
        options: ["will complete", "will have completed", "completed", "have completed"],
        answer: 1,
        explanation: "Future Perfect Tense"
    },
    {
        question: "He ______ the car for two hours when it broke down.",
        options: ["was driving", "has been driving", "had been driving", "drove"],
        answer: 2,
        explanation: "Past Perfect Continuous Tense"
    },
    {
        question: "Don't phone me between 7 and 8. We ______ dinner then.",
        options: ["will have", "will be having", "have", "had"],
        answer: 1,
        explanation: "Future Continuous Tense"
    },
    {
        question: "It ______ raining for three days.",
        options: ["is", "has been", "was", "had been"],
        answer: 1,
        explanation: "Present Perfect Continuous Tense"
    },
    {
        question: "Before he went to sleep, he ______ his homework.",
        options: ["finished", "has finished", "had finished", "finishes"],
        answer: 2,
        explanation: "Past Perfect Tense"
    },
    {
        question: "By the time you arrive, I ______ for two hours.",
        options: ["will wait", "will have been waiting", "have waited", "wait"],
        answer: 1,
        explanation: "Future Perfect Continuous Tense"
    },
    {
        question: "Someone ______ my cookies!",
        options: ["ate", "has eaten", "had eaten", "eats"],
        answer: 1,
        explanation: "Present Perfect Tense"
    },
    {
        question: "I ______ of buying a new house.",
        options: ["think", "am thinking", "thought", "have thought"],
        answer: 1,
        explanation: "Present Continuous Tense"
    },
    {
        question: "By 2025, we ______ here for 10 years.",
        options: ["will live", "will have been living", "are living", "have lived"],
        answer: 1,
        explanation: "Future Perfect Continuous Tense"
    },
    {
        question: "She ______ never ______ snow before she moved to Canada.",
        options: ["has / seen", "had / seen", "did / see", "was / seeing"],
        answer: 1,
        explanation: "Past Perfect Tense"
    },
    {
        question: "Look! The bus ______.",
        options: ["leaves", "is leaving", "left", "has left"],
        answer: 1,
        explanation: "Present Continuous Tense"
    },
    {
        question: "I ______ English for five years now.",
        options: ["study", "am studying", "have been studying", "studied"],
        answer: 2,
        explanation: "Present Perfect Continuous Tense"
    },
    {
        question: "The train ______ at 9 AM tomorrow.",
        options: ["leave", "leaves", "will leave", "is leaving"],
        answer: 1,
        explanation: "Simple Present Tense (Timetable)"
    },
    {
        question: "They ______ lunch when I got there.",
        options: ["had", "were having", "have had", "are having"],
        answer: 1,
        explanation: "Past Continuous Tense"
    },
    {
        question: "I promise I ______ help you.",
        options: ["will", "am going to", "shall", "would"],
        answer: 0,
        explanation: "Simple Future Tense"
    },
    {
        question: "This time next week, I ______ on the beach.",
        options: ["will lie", "will be lying", "am lying", "will have lain"],
        answer: 1,
        explanation: "Future Continuous Tense"
    },
    {
        question: "She ______ exhausted because she had been running.",
        options: ["is", "was", "has been", "will be"],
        answer: 1,
        explanation: "Simple Past Tense"
    },
    {
        question: "By next June, he ______ his book.",
        options: ["will write", "will have written", "writes", "has written"],
        answer: 1,
        explanation: "Future Perfect Tense"
    },
    {
        question: "How long ______ you ______ ?",
        options: ["are / waiting", "have / been waiting", "do / wait", "did / wait"],
        answer: 1,
        explanation: "Present Perfect Continuous Tense"
    }
];