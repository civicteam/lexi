const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const { DefinePlugin, ProvidePlugin } = require('webpack');

module.exports = {
  entry: './src/index.tsx',
  mode: 'development',
  module: {
    rules: [
      {
        test: /\.css$/i,
        use: ['style-loader', 'css-loader',{
          loader: "postcss-loader",
          options: {
            postcssOptions: {
              plugins: [
                require('tailwindcss'),
                require('autoprefixer'),
                [
                  "postcss-preset-env",
                  {
                    // Options
                  },
                ],
              ],
            },
          },
        },],
      },
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: path.join(__dirname, 'public', 'index.html')
    }),
    // Work around for Buffer is undefined:
    // https://github.com/webpack/changelog-v5/issues/10
    new ProvidePlugin({
      Buffer: ['buffer', 'Buffer'],
    }),
    new ProvidePlugin({
      process: 'process/browser',
    }),
    new DefinePlugin({
      'process.env': JSON.stringify({ }),
    })
  ],
  resolve: {
    alias: {
      process: "process/browser"
    },
    fallback: {
      assert: require.resolve('assert'),
      buffer: require.resolve('buffer'),
      stream: require.resolve('stream-browserify'),
      crypto: require.resolve('crypto-browserify'),
      os: require.resolve("os-browserify/browser"),
      http: require.resolve("stream-http"),
      url: require.resolve("url/"),
      https: require.resolve("https-browserify"),
      process: require.resolve('process/browser')
    },
    extensions: ['.tsx', '.ts', '.js'],
  },
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'dist'),
    clean: true,
  },
};
