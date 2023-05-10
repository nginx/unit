import cr from 'crypto';

export default {
    "num" : function () {return typeof cr.createHash('md5').digest().length}
}
