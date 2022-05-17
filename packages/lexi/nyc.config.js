module.exports = {
    all: true,
    include: "src/**",
    reporter: [
        "lcov",
        "html",
        "text"
    ],
    checkCoverage: true,
    lines: 100,
    functions: 100,
    statements: 100,
    branches: 100,
}
