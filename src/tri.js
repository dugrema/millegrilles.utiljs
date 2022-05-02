export function trierString(nomChamp, a, b, opts) {
    opts = opts || {}

    const nomA = a?a[nomChamp]:'',
          nomB = b?b[nomChamp]:''
    if(nomA === nomB) {
        if(opts.chaine) return opts.chaine(a, b)
        return 0
    }
    if(!nomA) return 1
    if(!nomB) return -1
    return nomA.localeCompare(nomB)
}

export function trierNombre(nomChamp, a, b, opts) {
    opts = opts || {}

    const tailleA = a?a[nomChamp]:'',
          tailleB = b?b[nomChamp]:''
    if(tailleA === tailleB) {
        if(opts.chaine) return opts.chaine()
        return 0    
    }
    if(!tailleA) return 1
    if(!tailleB) return -1
    return tailleA - tailleB
}
