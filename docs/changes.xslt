<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

<xsl:output method="text"/>

<xsl:param select="'generic'" name="format"/>
<xsl:param select="'unit'" name="pkgname"/>
<xsl:param select="'change_log_conf.xml'" name="configuration"/>
<xsl:param name="curdate"/>
<xsl:param name="curtime"/>

<xsl:variable select="document($configuration)/configuration" name="conf"/>

<xsl:variable name="start">
    <xsl:choose>
        <xsl:when test="$format='rpm'">
            <xsl:value-of select="$conf/rpm/start"/>
        </xsl:when>
        <xsl:when test="$format='deb'">
            <xsl:value-of select="$conf/deb/start"/>
        </xsl:when>
        <xsl:when test="$format='generic'">
            <xsl:value-of select="$conf/generic/start"/>
        </xsl:when>
    </xsl:choose>
</xsl:variable>

<xsl:variable name="indent">
    <xsl:choose>
        <xsl:when test="$format='rpm'">
            <xsl:value-of select="$conf/rpm/indent"/>
        </xsl:when>
        <xsl:when test="$format='deb'">
            <xsl:value-of select="$conf/deb/indent"/>
        </xsl:when>
        <xsl:when test="$format='generic'">
            <xsl:value-of select="$conf/generic/indent"/>
        </xsl:when>
    </xsl:choose>
</xsl:variable>

<xsl:variable name="max">
    <xsl:choose>
        <xsl:when test="$format='rpm'">
            <xsl:value-of select="$conf/rpm/length"/>
        </xsl:when>
        <xsl:when test="$format='deb'">
            <xsl:value-of select="$conf/deb/length"/>
        </xsl:when>
        <xsl:when test="$format='generic'">
            <xsl:value-of select="$conf/generic/length"/>
        </xsl:when>
    </xsl:choose>
</xsl:variable>

<xsl:variable name="br">&lt;br&gt;</xsl:variable>


<xsl:template match="/"> <xsl:apply-templates select="change_log"/> </xsl:template>
<xsl:template match="change_log"> <xsl:apply-templates select="changes"/> </xsl:template>


<xsl:template match="changes">
    <xsl:variable name="date_"> <xsl:call-template name="getdate"><xsl:with-param select="@date" name="date"/><xsl:with-param select="$curdate" name="curdate"/></xsl:call-template></xsl:variable>
    <xsl:variable name="time_"> <xsl:call-template name="gettime"><xsl:with-param select="@time" name="time"/><xsl:with-param select="$curtime" name="curtime"/></xsl:call-template></xsl:variable>
    <xsl:variable name="pday"> <xsl:call-template name="padded_day"><xsl:with-param select="$date_" name="date"/></xsl:call-template></xsl:variable>
    <xsl:variable name="dow"> <xsl:call-template name="day_of_week"><xsl:with-param select="$date_" name="date"/></xsl:call-template></xsl:variable>
    <xsl:variable name="apply"> <xsl:call-template name="string_in_list"><xsl:with-param select="@apply" name="list"/><xsl:with-param select="$pkgname" name="string"/></xsl:call-template></xsl:variable>
    <xsl:variable name="pkgname_"> <xsl:call-template name="beautify"><xsl:with-param select="$pkgname" name="pkgname"/></xsl:call-template></xsl:variable>

    <xsl:choose>
    <xsl:when test="$pkgname='unit' and $format='generic' and @rev!=1"/>
    <xsl:otherwise>
    <xsl:if test="$apply=$pkgname">

    <xsl:if test="$format='generic'">
        <xsl:text>&#10;</xsl:text>

        <xsl:value-of select="substring(concat($conf/changes/title,
                           $pkgname_,
                           ' ', @ver,
                           '                                                    '),
                    1, $conf/changes/length)"/>

        <xsl:value-of select="substring($date_, 9, 2)"/>
        <xsl:value-of select="$conf/changes/month[number(substring($date_, 6, 2))]"/>
        <xsl:value-of select="substring($date_, 1, 4)"/>
    </xsl:if>

    <xsl:if test="$format='rpm'">
        <xsl:value-of select="concat('* ', $conf/changes/day[number($dow)],
                 $conf/changes/month[number(substring($date_, 6, 2))],
                 $pday, ' ',
                 substring($date_, 1, 4), ' ', @packager, ' - ',
                 @ver, '-', @rev, '%{?dist}.ngx')"/>
    </xsl:if>

    <xsl:if test="$format='deb'">
        <xsl:value-of select="concat($pkgname, ' (', @ver, '-', @rev,
                 '~%%CODENAME%%) %%CODENAME%%; urgency=low')"/>

        <xsl:text>&#10;</xsl:text>
    </xsl:if>

    <xsl:text>&#10;</xsl:text>

    <xsl:apply-templates select="change"/>

    <xsl:text>&#10;</xsl:text>

    <xsl:if test="$format='deb'">
        <xsl:value-of select="concat(' -- ', @packager, '  ',
                 $conf/changes/day[number($dow)], ', ',
                 $pday,
                 $conf/changes/month[number(substring($date_, 6, 2))],
                 substring($date_, 1, 4), ' ', $time_)"/>

        <xsl:text>&#10;</xsl:text>
        <xsl:text>&#10;</xsl:text>
    </xsl:if>
    </xsl:if>
    </xsl:otherwise>
    </xsl:choose>
</xsl:template>


<xsl:template match="change">
    <xsl:variable select="$conf/changes/*[local-name(.)=current()/@type]" name="prefix"/>

    <xsl:variable name="postfix"> <xsl:if test="$prefix"> <xsl:text>: </xsl:text> </xsl:if> </xsl:variable>

    <xsl:apply-templates select="para"><xsl:with-param select="concat($start, $prefix, $postfix)" name="prefix"/></xsl:apply-templates>
</xsl:template>


<xsl:template name="para" match="para"><xsl:param name="prefix"/>
    <xsl:variable name="text"> <xsl:apply-templates/> </xsl:variable>

    <xsl:if test="$format='generic'">
        <xsl:text>&#10;</xsl:text>
    </xsl:if>

    <xsl:call-template name="wrap"><xsl:with-param select="normalize-space($text)" name="text"/><xsl:with-param name="prefix"> <xsl:choose><xsl:when test="position() = 1"> <xsl:value-of select="$prefix"/> </xsl:when><xsl:otherwise> <xsl:value-of select="$indent"/> </xsl:otherwise></xsl:choose> </xsl:with-param></xsl:call-template></xsl:template>


<xsl:template name="wrap"><xsl:param name="text"/><xsl:param name="prefix"/>
    <xsl:if test="$text">
        <xsl:variable name="offset">
            <xsl:choose>
                <xsl:when test="starts-with($text, concat($br, ' '))">
                    <xsl:value-of select="string-length($br) + 2"/>
                </xsl:when>
                <xsl:when test="starts-with($text, $br)">
                    <xsl:value-of select="string-length($br) + 1"/>
                </xsl:when>
                <xsl:otherwise>
                    1
                </xsl:otherwise>
            </xsl:choose>
        </xsl:variable>

        <xsl:variable name="length">
            <xsl:call-template name="length"><xsl:with-param select="substring($text, $offset)" name="text"/><xsl:with-param select="string-length($prefix)" name="prefix"/><xsl:with-param select="$max" name="length"/></xsl:call-template></xsl:variable>

        <xsl:value-of select="$prefix"/>

        <xsl:value-of select="normalize-space(translate(substring($text, $offset, $length),
                                    '&#xA0;', ' '))"/>

        <xsl:text>&#10;</xsl:text>

        <xsl:call-template name="wrap"><xsl:with-param select="substring($text, $length + $offset)" name="text"/><xsl:with-param select="$indent" name="prefix"/></xsl:call-template></xsl:if>
</xsl:template>


<xsl:template name="length"><xsl:param name="text"/><xsl:param name="prefix"/><xsl:param name="length"/>
    <xsl:variable select="substring-before(substring($text, 1,
                                    $length - $prefix + string-length($br)),
                                    $br)" name="break"/>

    <xsl:choose>
        <xsl:when test="$break"> <xsl:value-of select="string-length($break)"/> </xsl:when>

        <xsl:when test="$length = 0"> <xsl:value-of select="$max - $prefix"/> </xsl:when>

        <xsl:when test="string-length($text) + $prefix &lt;= $length">
            <xsl:value-of select="$length - $prefix"/>
        </xsl:when>

        <xsl:when test="substring($text, $length - $prefix + 1, 1) = ' '">
            <xsl:value-of select="$length - $prefix + 1"/>
        </xsl:when>

        <xsl:otherwise>
            <xsl:call-template name="length"><xsl:with-param select="$text" name="text"/><xsl:with-param select="$prefix" name="prefix"/><xsl:with-param select="$length - 1" name="length"/></xsl:call-template></xsl:otherwise>
    </xsl:choose>
</xsl:template>


<xsl:template name="day_of_week"><xsl:param name="date"/>
    <xsl:param select="substring-before($date, '-')" name="year"/>
    <xsl:param select="substring-before(substring-after($date, '-'), '-')" name="month"/>
    <xsl:param select="substring-after(substring-after($date, '-'), '-')" name="day"/>

    <xsl:variable select="floor((14 - $month) div 12)" name="a"/>

    <xsl:variable select="$year - $a" name="y"/>

    <xsl:variable select="$month + 12 * $a - 2" name="m"/>

    <xsl:value-of select="($day + $y + floor($y div 4) - floor($y div 100) 
    + floor($y div 400) + floor((31 * $m) div 12)) mod 7 + 1"/>
</xsl:template>


<xsl:template name="padded_day"><xsl:param name="date"/>
    <xsl:value-of select="substring(concat('  ', format-number(substring($date, 9, 2), '##')),
           1 + string-length(format-number(substring($date, 9, 2), '##')))"/>
</xsl:template>


<xsl:template name="string_in_list"><xsl:param name="list"/><xsl:param name="string"/>
    <xsl:choose>
        <xsl:when test="contains($list, ' ')">
            <xsl:variable select="substring-before($list, ' ')" name="str"/>
            <xsl:choose>
                <xsl:when test="$str=$string">
                    <xsl:value-of select="$string"/>
                </xsl:when>
                <xsl:otherwise>
                    <xsl:call-template name="string_in_list"><xsl:with-param select="substring-after($list, ' ')" name="list"/><xsl:with-param select="$string" name="string"/></xsl:call-template></xsl:otherwise>
            </xsl:choose>
        </xsl:when>
        <xsl:otherwise>
            <xsl:if test="$list=$string"> <xsl:value-of select="$string"/> </xsl:if>
            <xsl:if test="$list='*'"> <xsl:value-of select="$string"/> </xsl:if>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>


<xsl:template name="beautify"><xsl:param name="pkgname"/>
    <xsl:choose>
        <xsl:when test="$pkgname='unit'">Unit</xsl:when>
        <xsl:otherwise>
            <xsl:value-of select="$pkgname"/>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>


<xsl:template name="getdate"><xsl:param name="date"/><xsl:param name="curdate"/>
    <xsl:choose>
        <xsl:when test="$date=''">
            <xsl:value-of select="$curdate"/>
        </xsl:when>
        <xsl:otherwise>
            <xsl:value-of select="$date"/>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>


<xsl:template name="gettime"><xsl:param name="time"/><xsl:param name="curtime"/>
    <xsl:choose>
        <xsl:when test="$time=''">
            <xsl:value-of select="$curtime"/>
        </xsl:when>
        <xsl:otherwise>
            <xsl:value-of select="$time"/>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>


<xsl:template match="at">@</xsl:template>
<xsl:template match="br"> <xsl:value-of select="$br"/> </xsl:template>
<xsl:template match="nobr"> <xsl:value-of select="translate(., ' ', '&#xA0;')"/> </xsl:template>


</xsl:stylesheet>
