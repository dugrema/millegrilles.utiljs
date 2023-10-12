import mimetype_video from '../res/mimetype_video.json'

export function estMimetypeVideo(mimetype) {
    if(mimetype.startsWith('video/')) return true
    return mimetype_video.literal.includes(mimetype)
}
