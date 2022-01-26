const path = require('path');

module.exports = [];

// custom setup for each output
const outputs = [
  {
    entry: ['./src/index.js'],
    filenameBase: 'index'
  },
];

outputs.forEach(info => {
  // common to bundle and minified
  const common = {
    // each output uses the "forge" name but with different contents
    entry: {
      index: info.entry
    },
    // disable various node shims as forge handles this manually
    node: {
      // Buffer: false,
      // process: false,
      // crypto: false,
      // setImmediate: false
    }
  };

  // plain unoptimized unminified bundle
  const bundle = Object.assign({}, common, {
    mode: 'development',
    target: 'node',  // node ou web
    output: {
      path: path.join(__dirname, 'dist'),
      filename: info.filenameBase + '.js',
      library: info.library || '[name]',
      libraryTarget: info.libraryTarget || 'umd'
    }
  });
  if(info.library === null) {
    delete bundle.output.library;
  }
  if(info.libraryTarget === null) {
    delete bundle.output.libraryTarget;
  }

  // optimized and minified bundle
  const minify = Object.assign({}, common, {
    mode: 'production',
    target: 'web',
    output: {
      path: path.join(__dirname, 'dist'),
      filename: info.filenameBase + '.min.js',
      library: info.library || '[name]',
      libraryTarget: info.libraryTarget || 'umd'
    },
    devtool: 'cheap-module-source-map',
    plugins: [
      /*
      new webpack.optimize.UglifyJsPlugin({
        sourceMap: true,
        compress: {
          warnings: true
        },
        output: {
          comments: false
        }
        //beautify: true
      })
      */
    ]
  });
  if(info.library === null) {
    delete minify.output.library;
  }
  if(info.libraryTarget === null) {
    delete minify.output.libraryTarget;
  }

  module.exports.push(bundle);  // Version dev
  module.exports.push(minify);
});
